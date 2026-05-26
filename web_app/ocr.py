import os
import re


reader = None
_easyocr_error = None


def initialize_ocr_reader():
    global reader, _easyocr_error
    if reader is not None or _easyocr_error is not None:
        return reader
    try:
        import easyocr

        reader = easyocr.Reader(["en"])
    except Exception as exc:
        _easyocr_error = exc
        print(f"[OCR] Warning: EasyOCR unavailable: {exc}")
        reader = None
    return reader


def extract_text_from_image(image_path):
    """Extract text from image using EasyOCR when available."""
    try:
        from PIL import Image
        import numpy as np

        active_reader = initialize_ocr_reader()
        if not active_reader:
            print("[OCR] EasyOCR reader not initialized.")
            return None

        if not os.path.exists(image_path):
            print(f"[OCR] File not found: {image_path}")
            return None

        if os.path.getsize(image_path) > 50 * 1024 * 1024:
            print(f"[OCR] File too large: {image_path}")
            return None

        img = Image.open(image_path).convert("RGB")
        image_np = np.array(img)
        results = active_reader.readtext(image_np)
        extracted_text = " ".join([r[1] for r in results])
        if extracted_text and len(extracted_text.strip()) > 5:
            return extracted_text.strip()
        return None
    except ImportError as exc:
        print(f"[OCR] Missing OCR dependency: {exc}")
        return None
    except Exception as exc:
        print(f"[OCR] Exception: {type(exc).__name__}: {exc}")
        return None


def normalize_ocr_text(text):
    return re.sub(r"[^a-z0-9]+", "", text.lower())


def highlight_keywords_in_image(image_path, keywords, output_path):
    """Draw red highlights on keywords found in the image."""
    def draw_boxes(img, boxes):
        from PIL import Image, ImageDraw

        overlay = Image.new("RGBA", img.size, (0, 0, 0, 0))
        overlay_draw = ImageDraw.Draw(overlay)
        for box in boxes:
            overlay_draw.rounded_rectangle(box, radius=6, fill=(231, 76, 60, 92))
        highlighted = Image.alpha_composite(img, overlay).convert("RGB")
        outline = ImageDraw.Draw(highlighted)
        for box in boxes:
            outline.rounded_rectangle(box, radius=6, outline=(220, 38, 38), width=3)
        highlighted.save(output_path)
        return True

    normalized_keywords = [normalize_ocr_text(keyword) for keyword in keywords]

    try:
        from PIL import Image
        import pytesseract

        if not os.path.exists(image_path):
            return False

        img = Image.open(image_path).convert("RGBA")
        data = pytesseract.image_to_data(img, output_type=pytesseract.Output.DICT)

        words = []
        for i, raw_word in enumerate(data["text"]):
            normalized_word = normalize_ocr_text(raw_word)
            if not normalized_word:
                continue
            words.append(
                {
                    "text": normalized_word,
                    "left": data["left"][i],
                    "top": data["top"][i],
                    "width": data["width"][i],
                    "height": data["height"][i],
                }
            )

        hits = []
        for i, word in enumerate(words):
            for keyword in normalized_keywords:
                if word["text"] in keyword or keyword in word["text"]:
                    hits.append(word)
                elif i + 1 < len(words) and word["text"] + words[i + 1]["text"] == keyword:
                    hits.extend([word, words[i + 1]])

        if not hits:
            raise ValueError("No Tesseract keyword boxes found.")

        boxes = []
        for hit in hits:
            pad = 4
            boxes.append((
                hit["left"] - pad,
                hit["top"] - pad,
                hit["left"] + hit["width"] + pad,
                hit["top"] + hit["height"] + pad,
            ))

        return draw_boxes(img, boxes)
    except Exception as exc:
        print(f"[OCR Highlight] Tesseract path failed, trying EasyOCR fallback: {exc}")

    try:
        from PIL import Image

        active_reader = initialize_ocr_reader()
        if not active_reader or not os.path.exists(image_path):
            return False

        img = Image.open(image_path).convert("RGBA")
        results = active_reader.readtext(image_path)
        boxes = []
        for points, text, _confidence in results:
            normalized = normalize_ocr_text(text)
            if not normalized:
                continue
            if any(normalized in keyword or keyword in normalized for keyword in normalized_keywords):
                xs = [point[0] for point in points]
                ys = [point[1] for point in points]
                pad = 6
                boxes.append((
                    max(0, int(min(xs)) - pad),
                    max(0, int(min(ys)) - pad),
                    min(img.width, int(max(xs)) + pad),
                    min(img.height, int(max(ys)) + pad),
                ))

        if not boxes:
            return False
        return draw_boxes(img, boxes)
    except Exception as exc:
        print(f"[OCR Highlight] EasyOCR fallback failed: {exc}")
        return False
