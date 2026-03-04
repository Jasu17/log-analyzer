from src.analyzer import analyze_log

def main():
    analyze_log("/var/log/httpd/access_log")

if __name__ == "__main__":
    main()