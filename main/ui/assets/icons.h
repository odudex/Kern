#ifndef ICONS_H
#define ICONS_H

// Font Awesome symbol definitions (UTF-8 encoded).
// The generated 16/24/36 px icon fonts must include these codepoints.
#define ICON_XPUB "\xEE\x80\x81"        // Custom U+E001 = custom-xpub-key-badge
#define ICON_BITCOIN "\xEE\x82\xB4"     // FontAwesome U+E0B4 = bitcoin-sign
#define ICON_QR_CODE "\xEF\x80\xA9"     // FontAwesome U+F029 = qrcode
#define ICON_HELP "\xEF\x81\x99"        // FontAwesome U+F059 = circle-question
#define ICON_INFO "\xEF\x81\x9A"        // FontAwesome U+F05A = circle-info
#define ICON_KEY "\xEF\x82\x84"         // FontAwesome U+F084 = key
#define ICON_DERIVATION "\xEF\x84\xA6"  // FontAwesome U+F126 = code-branch
#define ICON_BOX_ARCHIVE "\xEF\x86\x87" // FontAwesome U+F187 = box-archive
#define ICON_TOOLBOX "\xEF\x95\x92"     // FontAwesome U+F552 = toolbox
#define ICON_FINGERPRINT "\xEF\x95\xB7" // FontAwesome U+F577 = fingerprint
#define ICON_DICE "\xEF\x94\xA2"        // FontAwesome U+F522 = dice
#define ICON_SD_CARD "\xEF\x9F\x82"     // FontAwesome U+F7C2 = sd-card

// Backward-compatible aliases for call sites that used size-named symbols.
#define ICON_QRCODE_36 ICON_QR_CODE
#define ICON_HELP_36 ICON_HELP
#define ICON_FINGERPRINT_36 ICON_FINGERPRINT

#endif // ICONS_H
