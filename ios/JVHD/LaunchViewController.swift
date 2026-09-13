/*
 * LaunchViewController.swift
 * Màn hình chờ trong lúc máy chủ cục bộ khởi động (thường < 0.3 giây).
 */

import UIKit

final class LaunchViewController: UIViewController {

    private let spinner = UIActivityIndicatorView(style: .large)
    private let titleLabel = UILabel()
    private let detailLabel = UILabel()

    override func viewDidLoad() {
        super.viewDidLoad()
        view.backgroundColor = UIColor(red: 0.027, green: 0.027, blue: 0.039, alpha: 1)

        titleLabel.text = "JVHD"
        titleLabel.textColor = .white
        titleLabel.font = .systemFont(ofSize: 42, weight: .bold)
        titleLabel.textAlignment = .center

        detailLabel.text = "Đang khởi động…"
        detailLabel.textColor = UIColor(white: 1, alpha: 0.65)
        detailLabel.font = .systemFont(ofSize: 15)
        detailLabel.textAlignment = .center
        detailLabel.numberOfLines = 0

        spinner.color = .white
        spinner.startAnimating()

        let stack = UIStackView(arrangedSubviews: [titleLabel, spinner, detailLabel])
        stack.axis = .vertical
        stack.alignment = .center
        stack.spacing = 18
        stack.translatesAutoresizingMaskIntoConstraints = false

        view.addSubview(stack)
        NSLayoutConstraint.activate([
            stack.centerXAnchor.constraint(equalTo: view.centerXAnchor),
            stack.centerYAnchor.constraint(equalTo: view.centerYAnchor),
            stack.leadingAnchor.constraint(greaterThanOrEqualTo: view.leadingAnchor, constant: 24),
            stack.trailingAnchor.constraint(lessThanOrEqualTo: view.trailingAnchor, constant: -24)
        ])
    }

    func showError(_ message: String) {
        spinner.stopAnimating()
        titleLabel.text = "Không khởi động được"
        detailLabel.text = message
    }
}
