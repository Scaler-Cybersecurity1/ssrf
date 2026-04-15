# SCALER SSRF Single Challenge

This project is a static SSRF challenge with one intercepted request, one query input, and one flag output.

## Problem Statement

The vulnerable backend pattern from `ssrf.txt` is:

`fetch(user_supplied_url)` without destination validation can force the backend to call internal services.

## Solution Overview

This site demonstrates vulnerable request handling where attacker-controlled URLs are fetched from the server side.

The demo includes:

1. **Single image fetch challenge** (`/api/media/fetch-image`)
2. **One payload input**
3. **One run action**
4. **One flag result**

## Interception Flow

- Open the demo and use the single intercepted request editor.
- Insert one JSON payload and run it.
- Observe the activity stream for SSRF behavior.
- One flag is shown in the same lab after each run.

## Run Locally

Open `index.html` in a browser.

## Notes

- This project is for legal security education only.
- The app is fully static and does not execute real backend attacks.
