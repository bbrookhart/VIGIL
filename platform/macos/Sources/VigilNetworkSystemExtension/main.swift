import Foundation
import NetworkExtension
import VigilNetworkAdapter

// Keep the provider module linked even though NetworkExtension instantiates it from Info.plist.
private let vigilProviderClass: AnyClass = VigilNetworkDataProvider.self
_ = vigilProviderClass

autoreleasepool {
    NEProvider.startSystemExtensionMode()
}

dispatchMain()
