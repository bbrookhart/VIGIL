import Darwin

enum NativeWallClock {
    static func nowUnixMilliseconds() -> Int64? {
        var timestamp = timespec()
        guard clock_gettime(CLOCK_REALTIME, &timestamp) == 0,
              timestamp.tv_sec >= 0,
              timestamp.tv_nsec >= 0
        else {
            return nil
        }
        let seconds = Int64(timestamp.tv_sec).multipliedReportingOverflow(by: 1_000)
        guard !seconds.overflow else {
            return nil
        }
        let milliseconds = seconds.partialValue.addingReportingOverflow(
            Int64(timestamp.tv_nsec) / 1_000_000
        )
        return milliseconds.overflow ? nil : milliseconds.partialValue
    }
}
