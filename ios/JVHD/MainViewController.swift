/*
 * MainViewController.swift
 * Màn hình chính: WKWebView nạp ứng dụng web JVHD từ máy chủ cục bộ.
 *
 *  - allowsInlineMediaPlayback = true  : phát video ngay trong trang (không
 *    bật lên trình phát toàn màn hình của Safari).
 *  - Cầu nối WKScriptMessageHandler     : nhận lệnh mở AVPlayer native.
 *  - Tự co giao diện 1920x1080 vừa màn hình iPhone (fit-to-screen), hỗ trợ
 *    pinch để phóng to, lắc thiết bị để tải lại.
 */

import AVFoundation
import SafariServices
import UIKit
import WebKit

final class MainViewController: UIViewController {

    // MARK: - Trạng thái

    private var webView: WKWebView!
    private let spinner = UIActivityIndicatorView(style: .large)
    private let statusLabel = UILabel()
    private let retryButton = UIButton(type: .system)
    private let nativePlayer = NativePlayer()

    private var zoomMultiplier: CGFloat = 1.0
    private var pinchStartZoom: CGFloat = 1.0
    private var lastBoundsSize: CGSize = .zero

    // MARK: - Vòng đời

    override func viewDidLoad() {
        super.viewDidLoad()
        view.backgroundColor = .black
        // Máy chủ dùng kích thước thật của view để tính tỉ lệ co giao diện
        // ngay khi phục vụ index.html (tránh giật hình lúc vừa mở app).
        LocalServer.viewportSizeProvider = { [weak self] in
            guard let self = self else { return UIScreen.main.bounds.size }
            let size = self.view.bounds.size
            return size.width > 0 ? size : UIScreen.main.bounds.size
        }
        configureAudioSession()
        configureWebView()
        configureOverlay()
        configureGestures()
        loadApp()
    }

    override func viewDidLayoutSubviews() {
        super.viewDidLayoutSubviews()
        if lastBoundsSize != view.bounds.size {
            lastBoundsSize = view.bounds.size
            applyFitToScreen()
        }
    }

    override var prefersStatusBarHidden: Bool { true }
    override var prefersHomeIndicatorAutoHidden: Bool { true }
    override var supportedInterfaceOrientations: UIInterfaceOrientationMask { .allButUpsideDown }

    // MARK: - Thiết lập

    private func configureAudioSession() {
        do {
            try AVAudioSession.sharedInstance().setCategory(.playback, mode: .moviePlayback, options: [.allowAirPlay])
        } catch {
            NSLog("[JVHD][audio] %@", error.localizedDescription)
        }
    }

    private func configureWebView() {
        let configuration = WKWebViewConfiguration()
        configuration.allowsInlineMediaPlayback = true          // phát ngay trong trang
        configuration.mediaTypesRequiringUserActionForPlayback = []   // tự phát (HLS autoplay)
        configuration.allowsAirPlayForMediaPlayback = true
        configuration.allowsPictureInPictureMediaPlayback = true
        if #available(iOS 14.0, *) {
            configuration.defaultWebpagePreferences.allowsContentJavaScript = true
        }
        configuration.websiteDataStore = .default()

        let controller = WKUserContentController()
        controller.add(ScriptMessageProxy(owner: self), name: JVHDConfig.scriptMessageNative)
        controller.add(ScriptMessageProxy(owner: self), name: JVHDConfig.scriptMessageLog)
        configuration.userContentController = controller

        let webView = WKWebView(frame: .zero, configuration: configuration)
        webView.translatesAutoresizingMaskIntoConstraints = false
        webView.navigationDelegate = self
        webView.uiDelegate = self
        webView.isOpaque = false
        webView.backgroundColor = .black
        webView.scrollView.backgroundColor = .black
        webView.scrollView.contentInsetAdjustmentBehavior = .never
        webView.scrollView.bounces = false
        webView.scrollView.pinchGestureRecognizer?.isEnabled = false // ta tự xử lý pinch
        webView.allowsBackForwardNavigationGestures = false
        view.addSubview(webView)

        NSLayoutConstraint.activate([
            webView.topAnchor.constraint(equalTo: view.topAnchor),
            webView.bottomAnchor.constraint(equalTo: view.bottomAnchor),
            webView.leadingAnchor.constraint(equalTo: view.leadingAnchor),
            webView.trailingAnchor.constraint(equalTo: view.trailingAnchor)
        ])
        self.webView = webView
    }

    private func configureOverlay() {
        spinner.translatesAutoresizingMaskIntoConstraints = false
        spinner.color = .white
        spinner.hidesWhenStopped = true
        view.addSubview(spinner)

        statusLabel.translatesAutoresizingMaskIntoConstraints = false
        statusLabel.textColor = UIColor(white: 1, alpha: 0.8)
        statusLabel.font = .systemFont(ofSize: 14)
        statusLabel.textAlignment = .center
        statusLabel.numberOfLines = 0
        statusLabel.alpha = 0
        view.addSubview(statusLabel)

        retryButton.translatesAutoresizingMaskIntoConstraints = false
        retryButton.setTitle("Thử lại", for: .normal)
        retryButton.setTitleColor(.white, for: .normal)
        retryButton.backgroundColor = UIColor(white: 1, alpha: 0.15)
        retryButton.layer.cornerRadius = 10
        retryButton.contentEdgeInsets = UIEdgeInsets(top: 10, left: 22, bottom: 10, right: 22)
        retryButton.alpha = 0
        retryButton.isHidden = true
        retryButton.addTarget(self, action: #selector(reloadTapped), for: .touchUpInside)
        view.addSubview(retryButton)

        NSLayoutConstraint.activate([
            spinner.centerXAnchor.constraint(equalTo: view.centerXAnchor),
            spinner.centerYAnchor.constraint(equalTo: view.centerYAnchor),
            statusLabel.centerXAnchor.constraint(equalTo: view.centerXAnchor),
            statusLabel.bottomAnchor.constraint(equalTo: view.bottomAnchor, constant: -80),
            statusLabel.leadingAnchor.constraint(greaterThanOrEqualTo: view.leadingAnchor, constant: 24),
            statusLabel.trailingAnchor.constraint(lessThanOrEqualTo: view.trailingAnchor, constant: -24),
            retryButton.centerXAnchor.constraint(equalTo: view.centerXAnchor),
            retryButton.topAnchor.constraint(equalTo: statusLabel.bottomAnchor, constant: 16)
        ])
    }

    private func configureGestures() {
        let pinch = UIPinchGestureRecognizer(target: self, action: #selector(handlePinch(_:)))
        pinch.delegate = self
        webView.addGestureRecognizer(pinch)

        let reloadGesture = UITapGestureRecognizer(target: self, action: #selector(handleTripleTap(_:)))
        reloadGesture.numberOfTouchesRequired = 3
        reloadGesture.numberOfTapsRequired = 1
        reloadGesture.delegate = self
        webView.addGestureRecognizer(reloadGesture)
    }

    // MARK: - Nạp ứng dụng

    private func loadApp() {
        let urlString = LocalServer.shared.baseURLString + "/index.html"
        guard let url = URL(string: urlString) else {
            showStatus("Không tạo được địa chỉ máy chủ cục bộ")
            return
        }
        spinner.startAnimating()
        webView.load(URLRequest(url: url, cachePolicy: .reloadIgnoringLocalCacheData, timeoutInterval: 30))
    }

    @objc private func reloadTapped() {
        retryButton.isHidden = true
        retryButton.alpha = 0
        statusLabel.alpha = 0
        loadApp()
    }

    @objc private func handleTripleTap(_ gesture: UITapGestureRecognizer) {
        showDebugMenu()
    }

    @objc private func handlePinch(_ gesture: UIPinchGestureRecognizer) {
        switch gesture.state {
        case .began:
            pinchStartZoom = zoomMultiplier
        case .changed:
            let next = pinchStartZoom * gesture.scale
            zoomMultiplier = min(JVHDConfig.maxFitScale, max(JVHDConfig.minFitScale, next))
            applyFitToScreen()
        case .ended, .cancelled, .failed:
            persistZoom()
        default:
            break
        }
    }

    override func motionEnded(_ motion: UIEvent.EventSubtype, with event: UIEvent?) {
        if motion == .motionShake { loadApp() }
    }

    // MARK: - Co vừa màn hình

    private func applyFitToScreen() {
        guard JVHDConfig.fitToScreen, webView != nil else { return }
        let size = view.bounds.size
        guard size.width > 0, size.height > 0 else { return }
        let base = min(size.width / JVHDConfig.designWidth, size.height / JVHDConfig.designHeight)
        let scale = min(JVHDConfig.maxFitScale, max(JVHDConfig.minFitScale, base * zoomMultiplier))
        let layoutWidth = size.width / scale
        let script = String(format: "if (window.__jvhdApplyFit) { window.__jvhdApplyFit(%.6f, %.2f); }", scale, layoutWidth)
        webView.evaluateJavaScript(script, completionHandler: nil)
    }

    private func persistZoom() {
        UserDefaults.standard.set(Float(zoomMultiplier), forKey: "jvhd.zoomMultiplier")
    }

    private func restoreZoom() {
        let stored = UserDefaults.standard.float(forKey: "jvhd.zoomMultiplier")
        zoomMultiplier = stored > 0 ? CGFloat(stored) : 1.0
    }

    // MARK: - Thông báo nhỏ

    private func showStatus(_ text: String, showRetry: Bool = false) {
        statusLabel.text = text
        retryButton.isHidden = !showRetry
        UIView.animate(withDuration: 0.2) {
            self.statusLabel.alpha = 1
            self.retryButton.alpha = showRetry ? 1 : 0
        }
    }

    private func showDebugMenu() {
        let sheet = UIAlertController(title: "JVHD", message: LocalServer.shared.baseURLString, preferredStyle: .actionSheet)
        sheet.addAction(UIAlertAction(title: "Tải lại", style: .default) { [weak self] _ in self?.loadApp() })
        sheet.addAction(UIAlertAction(title: "Về tỉ lệ gốc", style: .default) { [weak self] _ in
            self?.zoomMultiplier = 1.0
            self?.persistZoom()
            self?.applyFitToScreen()
        })
        sheet.addAction(UIAlertAction(title: "Xoá bộ nhớ web", style: .destructive) { [weak self] _ in
            let store = WKWebsiteDataStore.default()
            store.removeData(ofTypes: WKWebsiteDataStore.allWebsiteDataTypes(),
                             modifiedSince: Date(timeIntervalSince1970: 0)) { [weak self] in
                DispatchQueue.main.async { self?.loadApp() }
            }
        })
        sheet.addAction(UIAlertAction(title: "Đóng", style: .cancel))
        if let popover = sheet.popoverPresentationController {
            popover.sourceView = view
            popover.sourceRect = CGRect(x: view.bounds.midX, y: view.bounds.midY, width: 0, height: 0)
        }
        present(sheet, animated: true)
    }

    // MARK: - Xử lý thông điệp từ web

    fileprivate func handleScriptMessage(name: String, body: Any) {
        if name == JVHDConfig.scriptMessageLog {
            NSLog("[JVHD][web] %@", String(describing: body))
            return
        }
        guard let dictionary = body as? [String: Any], let action = dictionary["action"] as? String else { return }
        switch action {
        case "play":
            let url = dictionary["url"] as? String ?? ""
            let referer = dictionary["referer"] as? String ?? ""
            let title = dictionary["title"] as? String ?? "JVHD"
            nativePlayer.onDismissed = { [weak self] in
                self?.webView.evaluateJavaScript("window.__jvhdNativePlayerActive = false;", completionHandler: nil)
            }
            nativePlayer.play(urlString: url, referer: referer, title: title, from: self)
        case "close":
            nativePlayer.stop()
        case "toast":
            let text = dictionary["text"] as? String ?? ""
            showStatus(text)
            DispatchQueue.main.asyncAfter(deadline: .now() + 2.5) {
                UIView.animate(withDuration: 0.3) { self.statusLabel.alpha = 0 }
            }
        case "exit":
            // iOS không cho phép ứng dụng tự thoát: chỉ thông báo cho người dùng.
            showStatus("Nhấn nút Home để thoát JVHD")
        default:
            break
        }
    }

    private func openExternally(_ url: URL) {
        let safari = SFSafariViewController(url: url)
        present(safari, animated: true)
    }
}

// MARK: - WKNavigationDelegate

extension MainViewController: WKNavigationDelegate {

    func webView(_ webView: WKWebView, decidePolicyFor navigationAction: WKNavigationAction,
                 decisionHandler: @escaping (WKNavigationActionPolicy) -> Void) {
        guard let url = navigationAction.request.url else {
            decisionHandler(.allow)
            return
        }
        if let host = url.host, host == "127.0.0.1" || host == "localhost" {
            decisionHandler(.allow)
            return
        }
        // Mọi điều hướng ra ngoài bị chặn (giống bản Windows), liên kết do người
        // dùng bấm sẽ mở bằng SafariViewController.
        if navigationAction.navigationType == .linkActivated {
            openExternally(url)
        }
        decisionHandler(.cancel)
    }

    func webView(_ webView: WKWebView, didFinish navigation: WKNavigation!) {
        spinner.stopAnimating()
        statusLabel.alpha = 0
        retryButton.isHidden = true
        restoreZoom()
        applyFitToScreen()
    }

    func webView(_ webView: WKWebView, didFail navigation: WKNavigation!, withError error: Error) {
        spinner.stopAnimating()
        showStatus("Không tải được giao diện: \(error.localizedDescription)", showRetry: true)
    }

    func webView(_ webView: WKWebView, didFailProvisionalNavigation navigation: WKNavigation!, withError error: Error) {
        spinner.stopAnimating()
        showStatus("Không kết nối được máy chủ cục bộ: \(error.localizedDescription)", showRetry: true)
    }

    func webViewWebContentProcessDidTerminate(_ webView: WKWebView) {
        // iOS có thể huỷ tiến trình web khi thiếu bộ nhớ -> tải lại.
        loadApp()
    }
}

// MARK: - WKUIDelegate

extension MainViewController: WKUIDelegate {

    func webView(_ webView: WKWebView, createWebViewWith configuration: WKWebViewConfiguration,
                 for navigationAction: WKNavigationAction, windowFeatures: WKWindowFeatures) -> WKWebView? {
        if navigationAction.targetFrame == nil {
            webView.load(navigationAction.request)
        }
        return nil
    }

    func webView(_ webView: WKWebView, runJavaScriptAlertPanelWithMessage message: String,
                 initiatedByFrame frame: WKFrameInfo, completionHandler: @escaping () -> Void) {
        let alert = UIAlertController(title: "JVHD", message: message, preferredStyle: .alert)
        alert.addAction(UIAlertAction(title: "Đóng", style: .default) { _ in completionHandler() })
        present(alert, animated: true)
    }

    func webView(_ webView: WKWebView, runJavaScriptConfirmPanelWithMessage message: String,
                 initiatedByFrame frame: WKFrameInfo, completionHandler: @escaping (Bool) -> Void) {
        let alert = UIAlertController(title: "JVHD", message: message, preferredStyle: .alert)
        alert.addAction(UIAlertAction(title: "Huỷ", style: .cancel) { _ in completionHandler(false) })
        alert.addAction(UIAlertAction(title: "OK", style: .default) { _ in completionHandler(true) })
        present(alert, animated: true)
    }
}

// MARK: - UIGestureRecognizerDelegate

extension MainViewController: UIGestureRecognizerDelegate {
    func gestureRecognizer(_ gestureRecognizer: UIGestureRecognizer,
                           shouldRecognizeSimultaneouslyWith otherGestureRecognizer: UIGestureRecognizer) -> Bool {
        return true
    }
}

// MARK: - Tránh retain cycle với WKUserContentController

private final class ScriptMessageProxy: NSObject, WKScriptMessageHandler {
    weak var owner: MainViewController?
    init(owner: MainViewController) { self.owner = owner }
    func userContentController(_ userContentController: WKUserContentController, didReceive message: WKScriptMessage) {
        owner?.handleScriptMessage(name: message.name, body: message.body)
    }
}
