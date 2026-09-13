/*
 * NativePlayer.swift
 * Trình phát AVPlayer native (dự phòng khi hls.js không chạy được trong
 * WKWebView — iOS < 17.1 không có ManagedMediaSource).
 *
 * Luồng luôn đi qua proxy cục bộ của app nên AVPlayer nhận được đúng
 * Referer/User-Agent gốc mà không cần cấu hình header phức tạp.
 */

import AVFoundation
import AVKit
import UIKit

final class NativePlayer: NSObject, UIAdaptivePresentationControllerDelegate {

    private var playerViewController: AVPlayerViewController?
    private var player: AVPlayer?
    private var endObserver: NSObjectProtocol?

    var onDismissed: (() -> Void)?

    var isPresented: Bool { playerViewController != nil }

    func play(urlString: String, referer: String, title: String, from host: UIViewController) {
        guard let rawURL = URL(string: urlString) else { return }

        // Nếu chưa phải URL proxy cục bộ thì bọc qua proxy (giữ Referer/UA).
        let target: URL
        if let host = rawURL.host, host == "127.0.0.1" || host == "localhost" {
            target = rawURL
        } else {
            guard let proxied = URL(string: LocalServer.shared.proxyURL(for: urlString, referer: referer)) else { return }
            target = proxied
        }

        stop()

        let item = AVPlayerItem(url: target)
        let player = AVPlayer(playerItem: item)
        player.allowsExternalMediaPlayback = true
        player.usesExternalPlaybackWhileExternalScreenIsActive = true

        let controller = AVPlayerViewController()
        controller.player = player
        controller.allowsPictureInPicturePlayback = true
        if #available(iOS 14.2, *) {
            controller.canStartPictureInPictureAutomaticallyFromInline = true
        }
        controller.title = title
        controller.presentationController?.delegate = self

        self.player = player
        self.playerViewController = controller

        endObserver = NotificationCenter.default.addObserver(
            forName: .AVPlayerItemDidPlayToEndTime,
            object: item,
            queue: .main
        ) { [weak self] _ in
            self?.stop()
        }

        host.present(controller, animated: true) {
            do {
                try AVAudioSession.sharedInstance().setCategory(.playback, mode: .moviePlayback)
                try AVAudioSession.sharedInstance().setActive(true)
            } catch {
                NSLog("[JVHD][player] không kích hoạt được audio session: %@", error.localizedDescription)
            }
            player.play()
        }
    }

    func stop() {
        if let observer = endObserver {
            NotificationCenter.default.removeObserver(observer)
            endObserver = nil
        }
        let controller = playerViewController
        playerViewController = nil
        player?.pause()
        player = nil
        if let controller = controller, controller.presentingViewController != nil {
            controller.dismiss(animated: true, completion: nil)
        }
        onDismissed?()
    }

    // MARK: - UIAdaptivePresentationControllerDelegate

    func presentationControllerDidDismiss(_ presentationController: UIPresentationController) {
        if let observer = endObserver {
            NotificationCenter.default.removeObserver(observer)
            endObserver = nil
        }
        player?.pause()
        player = nil
        playerViewController = nil
        onDismissed?()
    }
}
