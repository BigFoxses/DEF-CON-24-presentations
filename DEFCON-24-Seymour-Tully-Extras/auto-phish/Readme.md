# Auto-Phish

A project that creates and posts phishing tweets to twitter users.

# Description

Many toolkits (e.g. SET) provide for automatically generating phishing payloads, but nothing currently exists to automatically generate front-end content to entice users to click on links. Furthermore, Twitter is an interesting attack surface: users provide a wealth of information which Twitter readily provides through a REST API, and due to character limitations, all links are shortened and grammar tends to be colloquial.

This project automatically generates spear-phishing tweets on Twitter. It uses two methods for generating text for the tweet: Markov models trained on the target's recent timeline statuses, and an LSTM Neural Network trained on a more general corpus. In order to evade detection, it also shortens the given payload using goo.gl and appends that to the tweet, prepends the tweet with an at mention, and triages users to those likely to be phished.

# Requirements
* Python 2.7
* Active Twitter developer API credentials, a Twitter account username and password, and a goo.gl API key (all to be placed in the corresponding variables in credentials.py)
* word-rnn, downloaded and installed from github.com/larspars/word-rnn

# To Run:
1. Clone this repository.
2. In the root of the repository, fill in credentials.py with your obtained credentials from the various services.
3. Download tweets_model.t7 and move into word-rnn/cv/
4. Obtain a list of twitter users that you wish to phish and a URL that you want them to click on.
5. Run pip install -r requirements.txt inside a virtual environment.
6. Run python auto-phish.py. The various options and parameters are available if you run python auto-phish.py -h.
