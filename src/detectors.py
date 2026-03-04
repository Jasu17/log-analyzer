from datetime import timedelta

WINDOW = timedelta(seconds=10)
THRESHOLD = 10

def detect_flood(ip_timestamps: dict):
    alerts = []

    for ip, timestamps in ip_timestamps.items():
        timestamps.sort()

        for i in range(len(timestamps)):
            count = 1

            for j in range(i + 1, len(timestamps)):
                if timestamps[j] - timestamps[i] <= WINDOW:
                    count += 1
                else:
                    break

            if count >= THRESHOLD:
                alerts.append(
                    f"Possible flood from {ip}: {count} requests in {WINDOW}"
                )
                break

    return alerts