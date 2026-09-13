/*
 * AppDelegate.swift
 * Điểm vào của ứng dụng iOS: khởi động máy chủ cục bộ rồi mở giao diện web.
 *
 * Không còn bất kỳ phụ thuộc Windows nào (.bat/.vbs/Node.js/Electron).
 */

import UIKit

@main
final class AppDelegate: UIResponder, UIApplicationDelegate {

    var window: UIWindow?

    func application(_ application: UIApplication,
                     didFinishLaunchingWithOptions launchOptions: [UIApplication.LaunchOptionsKey: Any]?) -> Bool {
        let window = UIWindow(frame: UIScreen.main.bounds)
        window.backgroundColor = .black
        let launchViewController = LaunchViewController()
        window.rootViewController = launchViewController
        window.makeKeyAndVisible()
        self.window = window

        LocalServer.shared.start { [weak self, weak launchViewController] result in
            DispatchQueue.main.async {
                switch result {
                case .success:
                    let main = MainViewController()
                    if let window = self?.window {
                        window.rootViewController = main
                    }
                case .failure(let error):
                    launchViewController?.showError(error.localizedDescription)
                }
            }
        }
        return true
    }

    func applicationDidEnterBackground(_ application: UIApplication) {
        // Dọn bớt bộ nhớ đệm của trình duyệt khi ứng dụng bị đưa về nền.
        URLCache.shared.removeAllCachedResponses()
    }
}
