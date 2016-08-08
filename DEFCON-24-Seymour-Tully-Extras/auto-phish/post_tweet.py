import time
import credentials
import argparse
from selenium import webdriver
from selenium.webdriver.common.keys import Keys

# Wait this long before pages load, in seconds
PAGE_LOAD_TIME = 2


# Posts a tweet using Selenium, instead of Twitter API, to avoid detection
# Very kludgey, but most UI things are
def post_tweet(text):
    driver = webdriver.PhantomJS()
    driver.set_window_size(1920, 1080)

    # Log in to twitter using provided twitter credentials
    login_page = driver.get("https://mobile.twitter.com/login")
    time.sleep(PAGE_LOAD_TIME)
    email_box = driver.find_element_by_id("session[username_or_email]")
    email_box.send_keys(credentials.username)
    password_box = driver.find_element_by_id("session[password]")
    password_box.send_keys(credentials.password + Keys.RETURN)
    time.sleep(PAGE_LOAD_TIME)

    # Compose and submit the new tweet
    driver.get("https://mobile.twitter.com/compose/tweet")
    time.sleep(PAGE_LOAD_TIME)
    tweet_box = driver.find_element_by_tag_name("textarea")
    tweet_box.click()
    tweet_box.send_keys(text)
    tweet_box.submit()
    time.sleep(PAGE_LOAD_TIME)

    # Cleanly shut everything down
    driver.quit()

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description="Posts a given tweet"
                                                 " to timeline of user given"
                                                 " in credentials.py")
    parser.add_argument("text", help="text to tweet")
    args = parser.parse_args()
    post_tweet(args.text)
