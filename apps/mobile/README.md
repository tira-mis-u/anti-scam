# AntiScam — React Native (Android, planned)

Chưa khởi tạo. Khi `npx react-native init` ở đây, hãy import logic dùng chung qua:

```
import { computeScore } from '../src/shared/heuristic';
import { collect }      from '../src/shared/features';   // chạy trong WebView
// (2 file trên được copy từ packages/*.js — xem npm script sync:shared)
```

Các module trên là bản copy của `packages/*.js` (tương tự cơ chế sync của
extension — mở rộng script `sync:shared` trong `package.json` khi cần).

Adapter cần viết riêng cho mobile:
- Thay `chrome.runtime.sendMessage` → `WebView.postMessage` bridge
- Thay `chrome.runtime.getURL`      → asset URI của RN
- Thay `chrome.storage.*`           → `AsyncStorage`
- Thay `chrome.tabs.update`         → router của app
