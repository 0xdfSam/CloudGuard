#!/usr/bin/env python3
"""
This script creates placeholder images for the documentation.
Run it from the repository root.
"""

import os
import sys
from pathlib import Path

try:
    from PIL import Image, ImageDraw, ImageFont
except ImportError:
    print("Error: Pillow is required to run this script.")
    print("Install it with: pip install Pillow")
    sys.exit(1)

def create_image(path, width, height, text, bg_color=(53, 108, 177), text_color=(255, 255, 255)):
    """Create a placeholder image with text."""
    img = Image.new('RGB', (width, height), color=bg_color)
    draw = ImageDraw.Draw(img)
    
    # Try to get a font, or use default
    try:
        font = ImageFont.truetype("arial.ttf", 36)
    except IOError:
        try:
            font = ImageFont.truetype("/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf", 36)
        except IOError:
            font = ImageFont.load_default()
    
    # Calculate text position for centering
    text_width, text_height = draw.textsize(text, font=font)
    position = ((width - text_width) // 2, (height - text_height) // 2)
    
    # Draw text
    draw.text(position, text, font=font, fill=text_color)
    
    # Save image
    os.makedirs(os.path.dirname(path), exist_ok=True)
    img.save(path)
    print(f"Created {path}")

def main():
    # Create docs/images directory if it doesn't exist
    docs_dir = Path("docs/images")
    docs_dir.mkdir(parents=True, exist_ok=True)
    
    # Create the logo
    create_image(
        "docs/images/cloudguard-logo.png", 
        600, 200, 
        "CloudGuard Logo"
    )
    
    # Create AWS and Azure service icons
    services_dir = docs_dir / "services"
    services_dir.mkdir(exist_ok=True)
    
    aws_services = ["s3", "iam", "ec2"]
    for service in aws_services:
        create_image(
            f"docs/images/services/aws-{service}.png",
            200, 200,
            f"AWS {service.upper()}"
        )
    
    azure_services = ["storage", "keyvault"]
    for service in azure_services:
        create_image(
            f"docs/images/services/azure-{service}.png",
            200, 200,
            f"Azure {service.title()}"
        )

if __name__ == "__main__":
    main()
    print("All placeholder images created successfully!")
    print("Replace these with actual images before releasing.") 