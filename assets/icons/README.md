# GQUIC Icons

This directory contains various sized versions of the GQUIC logo for different use cases.

## Available Sizes

| Size | File | Use Case |
|------|------|----------|
| 16x16 | `gquic-16.png` | Small UI elements, favicons |
| 32x32 | `gquic-32.png` | Toolbar icons, small buttons |
| 48x48 | `gquic-48.png` | Desktop icons, medium UI |
| 64x64 | `gquic-64.png` | Large buttons, app icons |
| 72x72 | `gquic-72.png` | Mobile app icons |
| 96x96 | `gquic-96.png` | High-DPI mobile icons |
| 128x128 | `gquic-128.png` | Large app icons, documentation |
| 256x256 | `gquic-256.png` | High-resolution displays |

## Special Files

- `gquic.ico` - Multi-size Windows ICO file (contains 16, 32, 48, 64, 128, 256px)
- `favicon.ico` - Web favicon (copy of gquic.ico)

## Usage Examples

### In HTML
```html
<link rel="icon" href="assets/icons/favicon.ico" type="image/x-icon">
<link rel="icon" href="assets/icons/gquic-32.png" sizes="32x32" type="image/png">
<link rel="icon" href="assets/icons/gquic-64.png" sizes="64x64" type="image/png">
```

### In Documentation
```markdown
![GQUIC Icon](assets/icons/gquic-64.png)
```

### In Desktop Applications
Use `gquic.ico` for Windows applications or select appropriate PNG sizes for other platforms.

## Generation

All icons were generated from the main `GQUIC-Logo.png` using ImageMagick:

```bash
magick assets/GQUIC-Logo.png -resize 64x64 assets/icons/gquic-64.png
```