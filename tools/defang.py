def defang(text: str) -> str:
    """Render IOCs safe to paste into logs/terminals."""
    return (text
            .replace("http://", "hxxp://")
            .replace("https://", "hxxps://")
            .replace(".", "[.]"))
