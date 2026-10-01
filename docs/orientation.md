# Orientation metadata and auto-rotation

The tested YPC stream embeds orientation information directly in each video
packet header.

## Packing

A 32-bit little-endian word beginning at video-header offset 6 contains three
signed sensor components. Each component is represented by a 9-bit magnitude
and a separate sign bit:

- bits 0..8: magnitude A
- bit 9: sign A
- bits 10..18: magnitude B
- bit 19: sign B
- bits 20..28: magnitude C
- bit 29: sign C

The working orientation angle is derived from components A and B using a
wrap-aware `atan2` calculation.

A physical one-turn calibration produced approximately one turn of decoded
angle, which confirmed this interpretation for the tested camera.

## Preview behaviour

When auto-rotation is enabled:

1. the current camera angle becomes the relative zero point;
2. subsequent angles are calculated with circular wrap handling;
3. the preview is counter-rotated;
4. rendering is clipped to the largest centered circle that is always visible
   regardless of rotation.

The circular viewport avoids rotating black/transparent corners entering the
visible image at intermediate angles.

## Saved photos and video

The same per-frame relative angle used for the live preview is associated with
each completed JPEG frame. When auto-rotation is enabled, still images and
recording frames are exported with the same counter-rotation and circular
viewport as the preview.

For a video recording the auto-rotation state is frozen when recording starts.
The UI disables the toggle until the recording has stopped, and the backend
also rejects mode changes while a recording is active. This avoids mixing
orientation modes inside one file and keeps frame processing deterministic.
