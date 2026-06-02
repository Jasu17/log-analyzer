from src.analyzer import analyze_log
import argparse

def main():
    parser = argparse.ArgumentParser(
        description="Web Log Security Analyzer"
    )

    parser.add_argument(
        "--file",
        default="/var/log/httpd/access_log",
        help="Path to log file (default: Apache access_log)"
    )

    parser.add_argument(
        "--output",
        default=None,
        help="Export report to JSON file"
    )

    parser.add_argument(
        "--only",
        nargs="+",
        choices=["flood", "sqli", "brute", "scan", "sensitive", "agent"],
        help="Filter alerts by type"
    )

    parser.add_argument(
        "--quiet",
        action="store_true",
        help="Supress console output (usefull with --output for scripting)"
    )

    args = parser.parse_args()

    analyze_log(args.file, args.output, args.only, args.quiet)

if __name__ == "__main__":
    main()