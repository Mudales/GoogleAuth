"""Telegram bot that decodes Google Authenticator export QR codes / migration URIs
into standard otpauth:// TOTP/HOTP URIs."""

import base64
import io
import logging
import os
from dataclasses import dataclass
from urllib.parse import parse_qs, quote, urlparse

import qrcode
from dotenv import load_dotenv
from PIL import Image
from pyzbar.pyzbar import decode as decode_qr
from telegram import Update
from telegram.constants import ParseMode
from telegram.ext import (
    ApplicationBuilder,
    CommandHandler,
    ContextTypes,
    MessageHandler,
    filters,
)

from migration_pb2 import MigrationPayload

load_dotenv()

logging.basicConfig(
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s", level=logging.INFO
)
logger = logging.getLogger(__name__)

ALLOWED_USER_IDS: set[int] = set()
_raw_ids = os.environ.get("ALLOWED_USER_IDS", "")
for _id in _raw_ids.split(","):
    _id = _id.strip()
    if _id.isdigit():
        ALLOWED_USER_IDS.add(int(_id))


class AllowedUserFilter(filters.BaseFilter):
    """Filter that only passes updates from allowed Telegram user IDs."""

    def filter(self, message) -> bool:
        if not ALLOWED_USER_IDS:
            return True  # no restriction if env var is empty
        if message.from_user and message.from_user.id in ALLOWED_USER_IDS:
            return True
        logger.warning(
            "Unauthorized access from user %s (@%s)",
            message.from_user.id if message.from_user else "unknown",
            message.from_user.username if message.from_user else "unknown",
        )
        return False


allowed_user = AllowedUserFilter()

ALGO_MAP = {0: "SHA1", 1: "SHA1", 2: "SHA256", 3: "SHA512", 4: "MD5"}
DIGITS_MAP = {0: "6", 1: "6", 2: "8"}
TYPE_MAP = {0: "totp", 1: "hotp", 2: "totp"}


@dataclass
class OtpEntry:
    name: str
    issuer: str
    secret: str
    otp_type: str
    algorithm: str
    digits: str
    counter: int
    uri: str


def decode_migration_uri(uri: str) -> list[OtpEntry]:
    """Decode an otpauth-migration:// URI into a list of OtpEntry objects."""
    parsed = urlparse(uri)
    data_param = parse_qs(parsed.query).get("data", [None])[0]
    if not data_param:
        raise ValueError("No 'data' parameter found in migration URI")

    raw = base64.b64decode(data_param)
    payload = MigrationPayload.from_bytes(raw)

    results = []
    for otp in payload.otp_parameters:
        secret = base64.b32encode(otp.secret).decode("ascii").rstrip("=")
        otp_type = TYPE_MAP.get(otp.type, "totp")
        algo = ALGO_MAP.get(otp.algorithm, "SHA1")
        digits = DIGITS_MAP.get(otp.digits, "6")
        issuer = otp.issuer or ""
        name = otp.name or ""

        if issuer and name:
            label = f"{quote(issuer)}:{quote(name)}"
        else:
            label = quote(name or issuer)

        uri_str = f"otpauth://{otp_type}/{label}?secret={secret}&issuer={quote(issuer)}&algorithm={algo}&digits={digits}"
        if otp_type == "hotp":
            uri_str += f"&counter={otp.counter}"

        results.append(OtpEntry(
            name=name,
            issuer=issuer,
            secret=secret,
            otp_type=otp_type,
            algorithm=algo,
            digits=digits,
            counter=otp.counter,
            uri=uri_str,
        ))

    return results


def generate_qr_image(data: str) -> bytes:
    """Generate a QR code PNG image as bytes."""
    qr = qrcode.QRCode(box_size=8, border=2)
    qr.add_data(data)
    qr.make(fit=True)
    img = qr.make_image(fill_color="black", back_color="white")
    buf = io.BytesIO()
    img.save(buf, format="PNG")
    buf.seek(0)
    return buf.getvalue()


def read_qr_from_image(image_bytes: bytes) -> list[str]:
    """Extract QR code text from image bytes."""
    img = Image.open(io.BytesIO(image_bytes))
    decoded = decode_qr(img)
    return [obj.data.decode("utf-8") for obj in decoded]


def format_entry_caption(entry: OtpEntry, index: int, total: int) -> str:
    """Format a caption for a single OTP entry."""
    header = f"🔑 {index}/{total}"
    issuer_line = f"Issuer:  {entry.issuer}" if entry.issuer else ""
    name_line = f"Name:  {entry.name}" if entry.name else ""
    secret_line = f"Secret:  `{entry.secret}`"
    type_line = f"Type:  {entry.otp_type.upper()}"

    lines = [header, ""]
    if issuer_line:
        lines.append(issuer_line)
    if name_line:
        lines.append(name_line)
    lines.append(secret_line)
    lines.append(type_line)
    lines.append("")
    lines.append(f"`{entry.uri}`")

    return "\n".join(lines)


async def send_otp_entries(message, entries: list[OtpEntry]) -> None:
    """Send each OTP entry as a separate message with QR code image."""
    total = len(entries)
    for i, entry in enumerate(entries, 1):
        caption = format_entry_caption(entry, i, total)
        qr_bytes = generate_qr_image(entry.uri)
        await message.reply_photo(
            photo=qr_bytes,
            caption=caption,
            parse_mode=ParseMode.MARKDOWN,
        )


async def start(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    await update.message.reply_text(
        "Send me a Google Authenticator export QR code photo "
        "or paste an otpauth-migration:// URI.\n\n"
        "I'll return each account as a separate message with "
        "a QR code and copyable secret.\n\n"
        "⚠️ Your secrets are sensitive — delete this chat when done."
    )


async def handle_photo(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    photo = update.message.photo[-1]
    file = await photo.get_file()
    image_bytes = await file.download_as_bytearray()

    qr_texts = read_qr_from_image(bytes(image_bytes))
    if not qr_texts:
        await update.message.reply_text("No QR code detected in the image.")
        return

    all_entries: list[OtpEntry] = []
    errors: list[str] = []

    for text in qr_texts:
        if text.startswith("otpauth-migration://"):
            try:
                all_entries.extend(decode_migration_uri(text))
            except Exception as e:
                logger.error("Failed to decode migration URI: %s", e)
                errors.append(f"Error decoding: {e}")
        elif text.startswith("otpauth://"):
            # Already a standard URI — parse minimal info and pass through
            all_entries.append(OtpEntry(
                name="", issuer="", secret="", otp_type="totp",
                algorithm="SHA1", digits="6", counter=0, uri=text,
            ))
        else:
            errors.append(f"Unrecognized QR content: {text[:100]}")

    if all_entries:
        await send_otp_entries(update.message, all_entries)
    elif errors:
        await update.message.reply_text("\n".join(errors))
    else:
        await update.message.reply_text("No OTP data found.")


async def handle_text(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    text = update.message.text.strip()

    if not text.startswith("otpauth-migration://"):
        await update.message.reply_text(
            "Please send an otpauth-migration:// URI or a QR code photo."
        )
        return

    try:
        entries = decode_migration_uri(text)
    except Exception as e:
        logger.error("Failed to decode: %s", e)
        await update.message.reply_text(f"Failed to decode: {e}")
        return

    if entries:
        await send_otp_entries(update.message, entries)
    else:
        await update.message.reply_text("No OTP entries found.")


async def error_handler(update: object, context: ContextTypes.DEFAULT_TYPE) -> None:
    logger.error("Exception while handling update: %s", context.error)


def main() -> None:
    token = os.environ.get("TELEGRAM_BOT_TOKEN")
    if not token:
        raise SystemExit("Set TELEGRAM_BOT_TOKEN environment variable")

    app = ApplicationBuilder().token(token).build()
    app.add_handler(CommandHandler("start", start, filters=allowed_user))
    app.add_handler(MessageHandler(filters.PHOTO & allowed_user, handle_photo))
    app.add_handler(MessageHandler(filters.TEXT & ~filters.COMMAND & allowed_user, handle_text))
    app.add_error_handler(error_handler)

    logger.info("Bot started")
    app.run_polling()


if __name__ == "__main__":
    main()
