#!/usr/bin/env python3
"""Generate extension icons"""
from PIL import Image, ImageDraw
import os

def create_icon(size):
    """Create a shield icon with a checkmark"""
    # Create image with transparent background
    img = Image.new('RGBA', (size, size), (0, 0, 0, 0))
    draw = ImageDraw.Draw(img)
    
    # Draw shield shape
    margin = size // 8
    shield_width = size - 2 * margin
    shield_height = size - margin
    
    # Shield outline (blue)
    shield_color = (52, 152, 219)  # Nice blue
    
    # Draw shield polygon
    points = [
        (margin, margin),  # top-left
        (size - margin, margin),  # top-right
        (size - margin, size // 2),  # middle-right
        (size // 2, size - margin),  # bottom
        (margin, size // 2),  # middle-left
    ]
    draw.polygon(points, fill=shield_color, outline=shield_color)
    
    # Draw checkmark (white)
    check_color = (255, 255, 255)
    check_margin = size // 4
    
    # Checkmark coordinates
    x1, y1 = size // 3, size // 2
    x2, y2 = size // 2 - 2, size - size // 4
    x3, y3 = size - size // 3, size // 3
    
    draw.line([(x1, y1), (x2, y2)], fill=check_color, width=max(2, size // 16))
    draw.line([(x2, y2), (x3, y3)], fill=check_color, width=max(2, size // 16))
    
    return img

# Create images directory if it doesn't exist
os.makedirs('images', exist_ok=True)

# Generate icons
sizes = [16, 48, 128]
for size in sizes:
    icon = create_icon(size)
    icon.save(f'images/icon-{size}.png')
    print(f'Created icon-{size}.png')

print('All icons generated successfully!')
