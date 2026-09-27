#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif

#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>

#include <algorithm>
#include <atomic>
#include <charconv>
#include <chrono>
#include <cstdint>
#include <memory>
#include <mutex>
#include <string>
#include <string_view>
#include <system_error>
#include <thread>
#include <utility>
#include <vector>

#pragma comment(lib, "Ws2_32.lib")

namespace {

constexpr UINT kUiEventMessage = WM_APP + 1;
constexpr int kConnectButtonId = 1001;
constexpr int kDisconnectButtonId = 1002;
constexpr std::size_t kMaxProtocolLine = 512;
constexpr auto kConnectTimeout = std::chrono::seconds(10);
constexpr auto kHandshakeTimeout = std::chrono::seconds(10);

struct Config {
    std::string serverHost;
    std::string serverPort;
    std::string localHost;
    std::string localPort;
    std::string token;
};

enum class UiEventKind { Log, Status, Finished };

struct UiEvent {
    UiEventKind kind;
    std::uint64_t sessionId;
    std::wstring text;
};

// 所有后台线程只使用 PostMessage 通知窗口。事件在窗口线程中释放，因此不会从
// 工作线程直接访问 EDIT/STATIC 控件，也不会跨线程调用 SendMessage 造成死锁。
void PostUiEvent(HWND window, UiEventKind kind, std::uint64_t id,
                 std::wstring message = {}) {
    auto* event = new UiEvent{kind, id, std::move(message)};
    if (!PostMessageW(window, kUiEventMessage, 0,
                      reinterpret_cast<LPARAM>(event))) {
        delete event;
    }
}

std::wstring SocketErrorText(int code = WSAGetLastError()) {
    // 保留 Windows 套接字错误码，方便排查；前面的描述始终使用中文。
    return L"网络错误（Winsock 错误码 " + std::to_wstring(code) + L"）";
}

bool WideToUtf8(const std::wstring& value, std::string& result) {
    result.clear();
    if (value.empty()) return true;
    const int length = WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS,
                                           value.data(),
                                           static_cast<int>(value.size()),
                                           nullptr, 0, nullptr, nullptr);
    if (length <= 0) return false;
    result.resize(static_cast<std::size_t>(length));
    return WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS, value.data(),
                               static_cast<int>(value.size()), result.data(),
                               length, nullptr, nullptr) == length;
}

std::wstring ReadEdit(HWND control) {
    // 直接读取控件当前的编辑缓冲区。密码框显示星号，但 WM_GETTEXT 仍会把
    // 实际内容交给同一进程的窗口线程。
    const int length = static_cast<int>(SendMessageW(control, WM_GETTEXTLENGTH,
                                                      0, 0));
    std::wstring value(static_cast<std::size_t>(length) + 1, L'\0');
    const int copied = static_cast<int>(SendMessageW(
        control, WM_GETTEXT, static_cast<WPARAM>(length + 1),
        reinterpret_cast<LPARAM>(value.data())));
    value.resize(static_cast<std::size_t>(copied));
    return value;
}

void Trim(std::wstring& text) {
    const auto first = text.find_first_not_of(L" \t\r\n");
    if (first == std::wstring::npos) {
        text.clear();
        return;
    }
    const auto last = text.find_last_not_of(L" \t\r\n");
    text = text.substr(first, last - first + 1);
}

bool ValidPort(const std::wstring& text) {
    if (text.empty() || text.size() > 5) return false;
    unsigned int number = 0;
    for (wchar_t ch : text) {
        if (ch < L'0' || ch > L'9') return false;
        number = number * 10 + static_cast<unsigned int>(ch - L'0');
    }
    return number >= 1 && number <= 65535;
}

bool ValidHost(const std::wstring& text) {
    if (text.empty() || text.size() > 253) return false;
    for (wchar_t ch : text) {
        if (ch <= L' ' || ch == L'\x7f') return false;
    }
    return true;
}

// 协议采用一行一个命令，token 是单个 ASCII 字段。拒绝空白和非 ASCII 字符，
// 避免把用户输入误解析为另一条 OPEN/DATA 命令或换行注入。
bool ValidToken(const std::wstring& text) {
    if (text.empty() || text.size() > 256) return false;
    for (wchar_t ch : text) {
        if (ch < L'!' || ch > L'~') return false;
    }
    return true;
}

class Session;

// SocketOwner 负责把套接字登记到 Session，并且仅由所属工作线程关闭。
// Disconnect 只调用 shutdown 唤醒阻塞的 recv/select，避免同时 closesocket。
class SocketOwner {
public:
    SocketOwner() = default;
    SocketOwner(Session& session, SOCKET socket, std::uint64_t epoch);
    SocketOwner(const SocketOwner&) = delete;
    SocketOwner& operator=(const SocketOwner&) = delete;
    SocketOwner(SocketOwner&& other) noexcept;
    SocketOwner& operator=(SocketOwner&& other) noexcept;
    ~SocketOwner();

    SOCKET Get() const { return socket_; }
    explicit operator bool() const { return socket_ != INVALID_SOCKET; }
    void Close();

private:
    Session* session_ = nullptr;
    SOCKET socket_ = INVALID_SOCKET;
};

class Session {
public:
    Session(HWND window, std::uint64_t id, Config config)
        : window_(window), id_(id), config_(std::move(config)) {}

    Session(const Session&) = delete;
    Session& operator=(const Session&) = delete;

    void Start() { manager_ = std::thread([this] { Run(); }); }
    void Join() {
        if (manager_.joinable()) manager_.join();
    }
    void RequestStop() {
        stopping_.store(true);
        ShutdownSockets();
    }
    std::uint64_t Id() const { return id_; }

    bool Cancelled(std::uint64_t epoch) const {
        return stopping_.load() || epoch_.load() != epoch;
    }

    void RegisterSocket(SOCKET socket, std::uint64_t epoch) {
        std::lock_guard<std::mutex> lock(socketsMutex_);
        sockets_.push_back(socket);
        // epoch 改变与 ShutdownSockets 之间可能并发创建套接字。登记时再检验
        // 一次，保证旧会话不会漏掉这只新创建的套接字。
        if (Cancelled(epoch)) shutdown(socket, SD_BOTH);
    }

    void CloseSocket(SOCKET socket) {
        std::lock_guard<std::mutex> lock(socketsMutex_);
        const auto it = std::find(sockets_.begin(), sockets_.end(), socket);
        if (it != sockets_.end()) sockets_.erase(it);
        closesocket(socket);
    }

private:
    friend class SocketOwner;

    void Log(std::wstring message) const {
        PostUiEvent(window_, UiEventKind::Log, id_, std::move(message));
    }
    void Status(std::wstring message) const {
        PostUiEvent(window_, UiEventKind::Status, id_, std::move(message));
    }

    void ShutdownSockets() {
        std::lock_guard<std::mutex> lock(socketsMutex_);
        for (SOCKET socket : sockets_) shutdown(socket, SD_BOTH);
    }

    // connect 使用非阻塞方式和短 select 周期。这样 DNS 解析结束后，即使服务端
    // 不可达，用户点击断开也能在约 200 ms 内中止连接等待。
    bool ConnectTcp(const std::string& host, const std::string& port,
                    std::uint64_t epoch, SocketOwner& destination,
                    std::wstring& error) {
        addrinfo hints{};
        hints.ai_family = AF_UNSPEC;
        hints.ai_socktype = SOCK_STREAM;
        hints.ai_protocol = IPPROTO_TCP;
        addrinfo* raw = nullptr;
        const int lookup = getaddrinfo(host.c_str(), port.c_str(), &hints, &raw);
        if (lookup != 0) {
            error = L"地址解析失败（错误码 " + std::to_wstring(lookup) + L"）";
            return false;
        }
        std::unique_ptr<addrinfo, decltype(&freeaddrinfo)> addresses(raw,
                                                                   freeaddrinfo);
        const auto deadline = std::chrono::steady_clock::now() + kConnectTimeout;
        for (addrinfo* address = addresses.get(); address && !Cancelled(epoch);
             address = address->ai_next) {
            const SOCKET socket = ::socket(address->ai_family,
                                           address->ai_socktype,
                                           address->ai_protocol);
            if (socket == INVALID_SOCKET) {
                error = SocketErrorText();
                continue;
            }
            SocketOwner candidate(*this, socket, epoch);
            u_long nonblocking = 1;
            if (ioctlsocket(socket, FIONBIO, &nonblocking) == SOCKET_ERROR) {
                error = SocketErrorText();
                continue;
            }

            int result = ::connect(socket, address->ai_addr,
                                   static_cast<int>(address->ai_addrlen));
            if (result == SOCKET_ERROR) {
                const int code = WSAGetLastError();
                if (code != WSAEWOULDBLOCK && code != WSAEINPROGRESS &&
                    code != WSAEALREADY) {
                    error = SocketErrorText(code);
                    continue;
                }
                while (!Cancelled(epoch) &&
                       std::chrono::steady_clock::now() < deadline) {
                    fd_set writable;
                    fd_set exceptional;
                    FD_ZERO(&writable);
                    FD_ZERO(&exceptional);
                    FD_SET(socket, &writable);
                    FD_SET(socket, &exceptional);
                    timeval wait{0, 200000};
                    result = select(0, nullptr, &writable, &exceptional, &wait);
                    if (result == 0) continue;
                    if (result == SOCKET_ERROR) {
                        error = SocketErrorText();
                        break;
                    }
                    int socketError = 0;
                    int length = sizeof(socketError);
                    if (getsockopt(socket, SOL_SOCKET, SO_ERROR,
                                   reinterpret_cast<char*>(&socketError),
                                   &length) == SOCKET_ERROR) {
                        error = SocketErrorText();
                        break;
                    }
                    if (socketError != 0) {
                        error = SocketErrorText(socketError);
                        break;
                    }
                    result = 0;
                    break;
                }
            }
            if (result != 0 || Cancelled(epoch)) continue;

            nonblocking = 0;
            if (ioctlsocket(socket, FIONBIO, &nonblocking) == SOCKET_ERROR) {
                error = SocketErrorText();
                continue;
            }
            const BOOL keepAlive = TRUE;
            setsockopt(socket, SOL_SOCKET, SO_KEEPALIVE,
                       reinterpret_cast<const char*>(&keepAlive),
                       sizeof(keepAlive));
            const BOOL noDelay = TRUE;
            setsockopt(socket, IPPROTO_TCP, TCP_NODELAY,
                       reinterpret_cast<const char*>(&noDelay),
                       sizeof(noDelay));
            destination = std::move(candidate);
            return true;
        }
        if (Cancelled(epoch)) error = L"操作已取消";
        else if (std::chrono::steady_clock::now() >= deadline)
            error = L"连接超时";
        return false;
    }

    bool SendLine(SOCKET socket, std::string_view line, std::uint64_t epoch) {
        std::size_t sent = 0;
        while (sent < line.size() && !Cancelled(epoch)) {
            fd_set writable;
            FD_ZERO(&writable);
            FD_SET(socket, &writable);
            timeval wait{0, 200000};
            const int ready = select(0, nullptr, &writable, nullptr, &wait);
            if (ready == 0) continue;
            if (ready == SOCKET_ERROR) return false;
            const int count = send(socket, line.data() + sent,
                                   static_cast<int>(line.size() - sent), 0);
            if (count <= 0) return false;
            sent += static_cast<std::size_t>(count);
        }
        return sent == line.size();
    }

    // 控制协议和 DATA 握手均限制为 512 字节一行。逐字节读取可保留 TCP
    // 流中下一条命令的数据，避免一次 recv 把多个 OPEN 合并后丢失。
    bool ReadLine(SOCKET socket, std::string& line,
                  std::uint64_t epoch,
                  std::chrono::steady_clock::time_point deadline =
                      std::chrono::steady_clock::time_point::max()) {
        line.clear();
        while (!Cancelled(epoch)) {
            if (std::chrono::steady_clock::now() >= deadline) return false;
            fd_set readable;
            FD_ZERO(&readable);
            FD_SET(socket, &readable);
            timeval wait{0, 200000};
            const int ready = select(0, &readable, nullptr, nullptr, &wait);
            if (ready == 0) continue;
            if (ready == SOCKET_ERROR) return false;
            char ch = 0;
            if (recv(socket, &ch, 1, 0) != 1) return false;
            if (ch == '\n') {
                if (!line.empty() && line.back() == '\r') line.pop_back();
                return true;
            }
            if (line.size() >= kMaxProtocolLine || ch == '\0') return false;
            line.push_back(ch);
        }
        return false;
    }

    static bool ParseOpen(const std::string& line, std::uint64_t& id) {
        if (line.rfind("OPEN ", 0) != 0) return false;
        const char* first = line.data() + 5;
        const char* last = line.data() + line.size();
        if (first == last) return false;
        const auto result = std::from_chars(first, last, id);
        return result.ec == std::errc{} && result.ptr == last;
    }

    // 每个方向各用一个线程传输原始字节。正常 EOF 只关闭对端的发送方向，
    // 使半关闭的 TCP 连接仍能把另一方向剩余的响应完整传回。
    void Pump(SOCKET source, SOCKET destination, std::uint64_t epoch) {
        char buffer[16 * 1024];
        while (!Cancelled(epoch)) {
            const int count = recv(source, buffer, sizeof(buffer), 0);
            if (count == 0) {
                shutdown(destination, SD_SEND);
                return;
            }
            if (count == SOCKET_ERROR) break;
            int offset = 0;
            while (offset < count && !Cancelled(epoch)) {
                const int written = send(destination, buffer + offset,
                                         count - offset, 0);
                if (written <= 0) break;
                offset += written;
            }
            if (offset != count) break;
        }
        // 错误或主动断开时唤醒同一隧道的另一方向，保证 join 不会无限等待。
        shutdown(source, SD_BOTH);
        shutdown(destination, SD_BOTH);
    }

    void RunTunnel(std::uint64_t id, std::uint64_t epoch) {
        SocketOwner local;
        SocketOwner data;
        std::wstring error;
        // 服务端仅为 OPEN 保留有限的等待时间，先认领 DATA，再连接本地目标。
        // 即使本地目标不可用，SocketOwner 离开作用域也会关闭已认领的数据连接。
        if (!ConnectTcp(config_.serverHost, config_.serverPort, epoch,
                        data, error)) {
            if (!Cancelled(epoch))
                Log(L"转发连接 " + std::to_wstring(id) +
                    L"：连接服务端失败：" + error);
            return;
        }
        const std::string command = "DATA " + config_.token + " " +
                                    std::to_string(id) + "\n";
        std::string reply;
        if (!SendLine(data.Get(), command, epoch) ||
            !ReadLine(data.Get(), reply, epoch,
                      std::chrono::steady_clock::now() + kHandshakeTimeout) ||
            reply != "OK") {
            if (!Cancelled(epoch))
                Log(L"转发连接 " + std::to_wstring(id) +
                    L"：服务端拒绝数据连接");
            return;
        }
        if (!ConnectTcp(config_.localHost, config_.localPort, epoch,
                        local, error)) {
            if (!Cancelled(epoch))
                Log(L"转发连接 " + std::to_wstring(id) +
                    L"：连接本地服务失败：" + error);
            return;
        }
        Log(L"转发连接 " + std::to_wstring(id) + L" 已建立");
        try {
            std::thread inbound([this, from = data.Get(), to = local.Get(), epoch] {
                Pump(from, to, epoch);
            });
            Pump(local.Get(), data.Get(), epoch);
            inbound.join();
        } catch (const std::system_error&) {
            shutdown(local.Get(), SD_BOTH);
            shutdown(data.Get(), SD_BOTH);
            Log(L"转发连接 " + std::to_wstring(id) +
                L"：无法启动转发线程");
        }
        Log(L"转发连接 " + std::to_wstring(id) + L" 已关闭");
    }

    void JoinTunnels() {
        for (TunnelWorker& tunnel : tunnels_) {
            if (tunnel.thread.joinable()) tunnel.thread.join();
        }
        tunnels_.clear();
    }

    void ReapFinishedTunnels() {
        // 控制连接可持续运行数月，不能只在断线时 join：每次收到命令时
        // 回收已完成的转发线程，避免线程句柄随访问次数无限累积。
        auto it = tunnels_.begin();
        while (it != tunnels_.end()) {
            if (it->finished->load()) {
                it->thread.join();
                it = tunnels_.erase(it);
            } else {
                ++it;
            }
        }
    }

    void StartTunnel(std::uint64_t tunnelId, std::uint64_t epoch) {
        auto finished = std::make_shared<std::atomic<bool>>(false);
        // 先为 vector 分配位置，再创建线程；若分配失败，不会遗留一个
        // joinable 的临时 std::thread 并触发 std::terminate。
        tunnels_.emplace_back();
        try {
            tunnels_.back().finished = finished;
            tunnels_.back().thread = std::thread([this, tunnelId, epoch, finished] {
                try {
                    RunTunnel(tunnelId, epoch);
                } catch (const std::exception&) {
                    Log(L"转发连接 " + std::to_wstring(tunnelId) +
                        L"：发生意外错误");
                }
                finished->store(true);
            });
        } catch (...) {
            tunnels_.pop_back();
            throw;
        }
    }

    void Run() {
        try {
            while (!stopping_.load()) {
                const std::uint64_t epoch = epoch_.load();
                SocketOwner control;
                std::wstring error;
                Status(L"连接中...");
                if (!ConnectTcp(config_.serverHost, config_.serverPort, epoch,
                                control, error)) {
                    if (!stopping_.load()) Log(L"连接服务端失败：" + error);
                } else {
                    std::string reply;
                    const std::string hello = "HELLO " + config_.token + "\n";
                    if (!SendLine(control.Get(), hello, epoch) ||
                        !ReadLine(control.Get(), reply, epoch,
                                  std::chrono::steady_clock::now() +
                                      kHandshakeTimeout)) {
                        if (!stopping_.load()) Log(L"与服务端握手失败");
                    } else if (reply != "OK") {
                        Log(L"服务端拒绝连接：请检查密钥和协议版本");
                        break;
                    } else {
                        Status(L"已连接");
                        Log(L"控制连接已建立");
                        std::string line;
                        while (!Cancelled(epoch) &&
                               ReadLine(control.Get(), line, epoch)) {
                            ReapFinishedTunnels();
                            if (line == "PING") {
                                if (!SendLine(control.Get(), "PONG\n", epoch))
                                    break;
                                continue;
                            }
                            std::uint64_t tunnelId = 0;
                            if (!ParseOpen(line, tunnelId)) {
                                Log(L"收到无效的控制命令");
                                break;
                            }
                            try {
                                StartTunnel(tunnelId, epoch);
                            } catch (const std::system_error&) {
                                Log(L"无法启动转发线程");
                            }
                        }
                        if (!stopping_.load()) Log(L"控制连接已断开");
                    }
                }

                // 控制连接丢失后先关闭旧数据连接并回收其线程，再重新 HELLO。
                // 这样新一轮会话不会继续使用旧会话里的 OPEN 编号。
                control.Close();
                epoch_.fetch_add(1);
                ShutdownSockets();
                JoinTunnels();
                if (stopping_.load()) break;
                Status(L"正在重连...");
                for (int i = 0; i < 20 && !stopping_.load(); ++i)
                    std::this_thread::sleep_for(std::chrono::milliseconds(100));
            }
        } catch (const std::exception&) {
            Log(L"客户端发生意外错误");
            RequestStop();
            JoinTunnels();
        }
        Status(L"未连接");
        PostUiEvent(window_, UiEventKind::Finished, id_);
    }

    HWND window_;
    std::uint64_t id_;
    Config config_;
    std::atomic<bool> stopping_{false};
    std::atomic<std::uint64_t> epoch_{1};
    std::mutex socketsMutex_;
    std::vector<SOCKET> sockets_;
    struct TunnelWorker {
        std::thread thread;
        std::shared_ptr<std::atomic<bool>> finished;
    };
    std::vector<TunnelWorker> tunnels_; // 只由 manager_ 创建和 join
    std::thread manager_;
};

SocketOwner::SocketOwner(Session& session, SOCKET socket, std::uint64_t epoch)
    : session_(&session), socket_(socket) {
    session_->RegisterSocket(socket_, epoch);
}

SocketOwner::SocketOwner(SocketOwner&& other) noexcept
    : session_(std::exchange(other.session_, nullptr)),
      socket_(std::exchange(other.socket_, INVALID_SOCKET)) {}

SocketOwner& SocketOwner::operator=(SocketOwner&& other) noexcept {
    if (this != &other) {
        Close();
        session_ = std::exchange(other.session_, nullptr);
        socket_ = std::exchange(other.socket_, INVALID_SOCKET);
    }
    return *this;
}

SocketOwner::~SocketOwner() { Close(); }

void SocketOwner::Close() {
    if (socket_ != INVALID_SOCKET) {
        session_->CloseSocket(socket_);
        socket_ = INVALID_SOCKET;
        session_ = nullptr;
    }
}

struct App {
    HWND window = nullptr;
    HWND serverHost = nullptr;
    HWND serverPort = nullptr;
    HWND localHost = nullptr;
    HWND localPort = nullptr;
    HWND token = nullptr;
    HWND connectButton = nullptr;
    HWND disconnectButton = nullptr;
    HWND status = nullptr;
    HWND log = nullptr;
    HWND labels[6]{};
    std::uint64_t nextSessionId = 1;
    Session* active = nullptr;
    std::vector<std::unique_ptr<Session>> sessions;
};

void AppendLog(HWND control, const std::wstring& message) {
    SYSTEMTIME now{};
    GetLocalTime(&now);
    wchar_t time[16];
    wsprintfW(time, L"[%02u:%02u:%02u] ", now.wHour, now.wMinute,
              now.wSecond);
    const int length = GetWindowTextLengthW(control);
    if (length > 60000) {
        // 长时间运行时保留近期日志，避免 EDIT 控件和窗口进程无限增长。
        SendMessageW(control, EM_SETSEL, 0, length - 40000);
        SendMessageW(control, EM_REPLACESEL, FALSE,
                     reinterpret_cast<LPARAM>(L""));
    }
    SendMessageW(control, EM_SETSEL, GetWindowTextLengthW(control),
                 GetWindowTextLengthW(control));
    const std::wstring line = std::wstring(time) + message + L"\r\n";
    SendMessageW(control, EM_REPLACESEL, FALSE,
                 reinterpret_cast<LPARAM>(line.c_str()));
}

void UpdateButtons(App& app) {
    EnableWindow(app.connectButton, app.active == nullptr);
    EnableWindow(app.disconnectButton, app.active != nullptr);
}

void Layout(App& app, int width, int height) {
    const int margin = 16;
    const int inputLeft = 126;
    const int rightColumn = std::max(405, width - 300);
    const int hostWidth = std::max(150, rightColumn - inputLeft - 18);
    const int portLeft = rightColumn + 94;
    const int portWidth = std::max(80, width - portLeft - margin);
    MoveWindow(app.labels[0], margin, 20, 105, 22, TRUE);
    MoveWindow(app.serverHost, inputLeft, 16, hostWidth, 25, TRUE);
    MoveWindow(app.labels[1], rightColumn, 20, 90, 22, TRUE);
    MoveWindow(app.serverPort, portLeft, 16, portWidth, 25, TRUE);
    MoveWindow(app.labels[2], margin, 56, 105, 22, TRUE);
    MoveWindow(app.localHost, inputLeft, 52, hostWidth, 25, TRUE);
    MoveWindow(app.labels[3], rightColumn, 56, 90, 22, TRUE);
    MoveWindow(app.localPort, portLeft, 52, portWidth, 25, TRUE);
    MoveWindow(app.labels[4], margin, 92, 105, 22, TRUE);
    MoveWindow(app.token, inputLeft, 88, width - inputLeft - margin, 25,
               TRUE);
    MoveWindow(app.connectButton, inputLeft, 127, 100, 28, TRUE);
    MoveWindow(app.disconnectButton, inputLeft + 110, 127, 110, 28, TRUE);
    MoveWindow(app.status, inputLeft + 232, 132,
               std::max(80, width - inputLeft - 232 - margin), 22, TRUE);
    MoveWindow(app.labels[5], margin, 174, 105, 22, TRUE);
    MoveWindow(app.log, margin, 198, std::max(100, width - 2 * margin),
               std::max(80, height - 198 - margin), TRUE);
}

HWND MakeControl(HWND parent, DWORD exStyle, const wchar_t* className,
                 const wchar_t* text, DWORD style, int id = 0) {
    HWND control = CreateWindowExW(exStyle, className, text,
                                   WS_CHILD | WS_VISIBLE | style,
                                   0, 0, 1, 1, parent,
                                   reinterpret_cast<HMENU>(
                                       static_cast<INT_PTR>(id)),
                                   GetModuleHandleW(nullptr), nullptr);
    SendMessageW(control, WM_SETFONT,
                 reinterpret_cast<WPARAM>(GetStockObject(DEFAULT_GUI_FONT)),
                 TRUE);
    return control;
}

void CreateControls(App& app) {
    // 控件使用 Unicode API，中文标签与状态不会受系统 ANSI 代码页影响。
    app.labels[0] = MakeControl(app.window, 0, L"STATIC", L"服务端地址",
                                SS_LEFT);
    app.labels[1] = MakeControl(app.window, 0, L"STATIC", L"控制端口",
                                SS_LEFT);
    app.labels[2] = MakeControl(app.window, 0, L"STATIC", L"本地地址",
                                SS_LEFT);
    app.labels[3] = MakeControl(app.window, 0, L"STATIC", L"本地端口",
                                SS_LEFT);
    app.labels[4] = MakeControl(app.window, 0, L"STATIC", L"连接密钥",
                                SS_LEFT);
    app.labels[5] = MakeControl(app.window, 0, L"STATIC", L"运行日志",
                                SS_LEFT);
    const DWORD editStyle = ES_AUTOHSCROLL | WS_TABSTOP;
    app.serverHost = MakeControl(app.window, WS_EX_CLIENTEDGE, L"EDIT",
                                 L"127.0.0.1", editStyle);
    app.serverPort = MakeControl(app.window, WS_EX_CLIENTEDGE, L"EDIT",
                                 L"7000", editStyle | ES_NUMBER);
    app.localHost = MakeControl(app.window, WS_EX_CLIENTEDGE, L"EDIT",
                                L"127.0.0.1", editStyle);
    app.localPort = MakeControl(app.window, WS_EX_CLIENTEDGE, L"EDIT",
                                L"8080", editStyle | ES_NUMBER);
    app.token = MakeControl(app.window, WS_EX_CLIENTEDGE, L"EDIT", L"",
                            editStyle | ES_PASSWORD);
    app.connectButton = MakeControl(app.window, 0, L"BUTTON", L"连接",
                                    BS_PUSHBUTTON | WS_TABSTOP,
                                    kConnectButtonId);
    app.disconnectButton = MakeControl(app.window, 0, L"BUTTON",
                                       L"断开",
                                       BS_PUSHBUTTON | WS_TABSTOP,
                                       kDisconnectButtonId);
    app.status = MakeControl(app.window, 0, L"STATIC", L"未连接",
                             SS_LEFT);
    app.log = MakeControl(app.window, WS_EX_CLIENTEDGE, L"EDIT", L"",
                          ES_MULTILINE | ES_READONLY | ES_AUTOVSCROLL |
                              WS_VSCROLL);
    SendMessageW(app.log, EM_LIMITTEXT, 1000000, 0);
    UpdateButtons(app);
}

bool ReadConfig(App& app, Config& config, std::wstring& error) {
    std::wstring serverHost = ReadEdit(app.serverHost);
    std::wstring serverPort = ReadEdit(app.serverPort);
    std::wstring localHost = ReadEdit(app.localHost);
    std::wstring localPort = ReadEdit(app.localPort);
    std::wstring token = ReadEdit(app.token);
    Trim(serverHost);
    Trim(serverPort);
    Trim(localHost);
    Trim(localPort);
    Trim(token);
    if (!ValidHost(serverHost) || !ValidHost(localHost)) {
        error = L"请输入有效的服务端地址和本地地址。";
        return false;
    }
    if (!ValidPort(serverPort) || !ValidPort(localPort)) {
        error = L"端口必须是 1 到 65535 之间的整数。";
        return false;
    }
    if (!ValidToken(token)) {
        error = L"连接密钥必须为 1 至 256 个可见 ASCII 字符，不能包含空格。";
        return false;
    }
    if (!WideToUtf8(serverHost, config.serverHost) ||
        !WideToUtf8(serverPort, config.serverPort) ||
        !WideToUtf8(localHost, config.localHost) ||
        !WideToUtf8(localPort, config.localPort) ||
        !WideToUtf8(token, config.token)) {
        error = L"无法将输入内容编码为 UTF-8。";
        return false;
    }
    return true;
}

void Connect(App& app) {
    if (app.active) return;
    Config config;
    std::wstring error;
    if (!ReadConfig(app, config, error)) {
        MessageBoxW(app.window, error.c_str(), L"设置无效",
                    MB_OK | MB_ICONWARNING);
        return;
    }
    auto session = std::make_unique<Session>(app.window, app.nextSessionId++,
                                             std::move(config));
    app.active = session.get();
    app.sessions.push_back(std::move(session));
    UpdateButtons(app);
    SetWindowTextW(app.status, L"连接中...");
    AppendLog(app.log, L"正在启动客户端");
    try {
        app.active->Start();
    } catch (const std::system_error&) {
        app.sessions.pop_back();
        app.active = nullptr;
        UpdateButtons(app);
        SetWindowTextW(app.status, L"未连接");
        AppendLog(app.log, L"无法启动连接线程");
    }
}

void Disconnect(App& app) {
    if (!app.active) return;
    app.active->RequestStop();
    app.active = nullptr;
    UpdateButtons(app);
    SetWindowTextW(app.status, L"正在断开...");
    AppendLog(app.log, L"已请求断开连接");
}

void HandleUiEvent(App& app, std::unique_ptr<UiEvent> event) {
    if (event->kind == UiEventKind::Log) {
        AppendLog(app.log, event->text);
    } else if (event->kind == UiEventKind::Status) {
        if (app.active && app.active->Id() == event->sessionId)
            SetWindowTextW(app.status, event->text.c_str());
    } else {
        const auto it = std::find_if(
            app.sessions.begin(), app.sessions.end(),
            [&](const std::unique_ptr<Session>& session) {
                return session->Id() == event->sessionId;
            });
        if (it == app.sessions.end()) return;
        // Finished 由 manager 线程最后发送；join 后才销毁 Session，避免窗口
        // 退出或快速重连时的悬空指针和仍在运行的套接字线程。
        (*it)->Join();
        if (app.active == it->get()) app.active = nullptr;
        if (!app.active) {
            UpdateButtons(app);
            SetWindowTextW(app.status, L"未连接");
        }
        app.sessions.erase(it);
    }
}

LRESULT CALLBACK WindowProc(HWND window, UINT message, WPARAM wParam,
                            LPARAM lParam) {
    App* app = reinterpret_cast<App*>(GetWindowLongPtrW(window, GWLP_USERDATA));
    if (message == WM_NCCREATE) {
        const auto* create = reinterpret_cast<CREATESTRUCTW*>(lParam);
        app = static_cast<App*>(create->lpCreateParams);
        app->window = window;
        SetWindowLongPtrW(window, GWLP_USERDATA,
                          reinterpret_cast<LONG_PTR>(app));
        return TRUE;
    }
    if (!app) return DefWindowProcW(window, message, wParam, lParam);

    switch (message) {
    case WM_CREATE: {
        CreateControls(*app);
        RECT client{};
        GetClientRect(window, &client);
        Layout(*app, client.right, client.bottom);
        return 0;
    }
    case WM_SIZE:
        Layout(*app, LOWORD(lParam), HIWORD(lParam));
        return 0;
    case WM_GETMINMAXINFO: {
        auto* limits = reinterpret_cast<MINMAXINFO*>(lParam);
        limits->ptMinTrackSize = POINT{720, 500};
        return 0;
    }
    case WM_COMMAND:
        if (HIWORD(wParam) == BN_CLICKED) {
            if (LOWORD(wParam) == kConnectButtonId) Connect(*app);
            if (LOWORD(wParam) == kDisconnectButtonId) Disconnect(*app);
        }
        return 0;
    case kUiEventMessage:
        HandleUiEvent(*app,
                      std::unique_ptr<UiEvent>(reinterpret_cast<UiEvent*>(lParam)));
        return 0;
    case WM_CLOSE:
        DestroyWindow(window);
        return 0;
    case WM_DESTROY: {
        // 先请求全部会话停止，再 join。SocketOwner 的关闭和 Winsock 清理由
        // 工作线程及 wWinMain 完成，确保 WSACleanup 不早于任何网络线程。
        for (auto& session : app->sessions) session->RequestStop();
        for (auto& session : app->sessions) session->Join();
        app->sessions.clear();
        app->active = nullptr;
        // 清除已经排队的堆分配 UI 事件，避免退出消息循环时遗留消息对象。
        MSG pending{};
        while (PeekMessageW(&pending, window, kUiEventMessage,
                            kUiEventMessage, PM_REMOVE)) {
            delete reinterpret_cast<UiEvent*>(pending.lParam);
        }
        PostQuitMessage(0);
        return 0;
    }
    default:
        return DefWindowProcW(window, message, wParam, lParam);
    }
}

} // namespace

int WINAPI wWinMain(HINSTANCE instance, HINSTANCE, PWSTR, int showCommand) {
    WSADATA winsock{};
    if (WSAStartup(MAKEWORD(2, 2), &winsock) != 0) {
        MessageBoxW(nullptr, L"无法初始化 Windows 网络组件。", L"内网穿透客户端",
                    MB_OK | MB_ICONERROR);
        return 1;
    }

    const wchar_t* className = L"ReversePortForwardClientWindow";
    WNDCLASSW windowClass{};
    windowClass.lpfnWndProc = WindowProc;
    windowClass.hInstance = instance;
    windowClass.lpszClassName = className;
    windowClass.hCursor = LoadCursorW(nullptr, IDC_ARROW);
    windowClass.hbrBackground = reinterpret_cast<HBRUSH>(COLOR_WINDOW + 1);
    if (!RegisterClassW(&windowClass)) {
        WSACleanup();
        return 1;
    }

    App app;
    HWND window = CreateWindowExW(
        0, className, L"TCP 内网穿透客户端",
        WS_OVERLAPPEDWINDOW, CW_USEDEFAULT, CW_USEDEFAULT, 760, 550,
        nullptr, nullptr, instance, &app);
    if (!window) {
        WSACleanup();
        return 1;
    }
    ShowWindow(window, showCommand);
    UpdateWindow(window);

    MSG message{};
    while (GetMessageW(&message, nullptr, 0, 0) > 0) {
        TranslateMessage(&message);
        DispatchMessageW(&message);
    }
    WSACleanup();
    return static_cast<int>(message.wParam);
}
