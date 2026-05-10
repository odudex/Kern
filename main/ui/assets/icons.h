#ifndef ICONS_H
#define ICONS_H

// Font Awesome symbol definitions (UTF-8 encoded).
// The generated 16/24/36 px icon fonts must include these codepoints.
#define ICON_BITCOIN "\xEE\x82\xB4"     // FontAwesome U+E0B4 = bitcoin-sign
#define ICON_QR_CODE "\xEF\x80\xA9"     // FontAwesome U+F029 = qrcode
#define ICON_HELP "\xEF\x81\x99"        // FontAwesome U+F059 = circle-question
#define ICON_DERIVATION "\xEF\x84\xA6"  // FontAwesome U+F126 = code-branch
#define ICON_FINGERPRINT "\xEF\x95\xB7" // FontAwesome U+F577 = fingerprint

// Backward-compatible aliases for call sites that used size-named symbols.
#define ICON_QRCODE_36 ICON_QR_CODE
#define ICON_HELP_36 ICON_HELP
#define ICON_FINGERPRINT_36 ICON_FINGERPRINT

#endif // ICONS_H
