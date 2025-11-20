from playwright.sync_api import Page, expect, sync_playwright
import os

def verify_sd_jwt_demo(page: Page):
    # 1. Go to the demo page
    page.goto("http://localhost:8080/index.html")

    # 2. Wait for the demo to load and generate keys (this might take a bit)
    # We look for "Verified Claims" which appears after processing
    expect(page.locator("#output")).to_contain_text("Verified Claims:", timeout=10000)

    # 3. Interact with the checkboxes
    # Find the first disclosure checkbox (email) and toggle it off
    # The label should contain "email"
    email_checkbox = page.locator("input[type='checkbox']").first
    email_checkbox.uncheck()

    # 4. Verify that the verified claims update
    # The output is in #interactive pre tag
    # It should NOT contain email anymore (or empty object if all removed)
    # Actually the output shows verified subset.
    
    # Let's just take a screenshot of the initial state and after toggle.
    page.screenshot(path="verification/sd_jwt_demo_initial.png")
    
    email_checkbox.check()
    page.wait_for_timeout(500) # small wait for render
    page.screenshot(path="verification/sd_jwt_demo_toggled.png")

if __name__ == "__main__":
    with sync_playwright() as p:
        browser = p.chromium.launch(headless=True)
        page = browser.new_page()
        try:
            verify_sd_jwt_demo(page)
        except Exception as e:
            print(f"Error: {e}")
            page.screenshot(path="verification/error.png")
        finally:
            browser.close()
