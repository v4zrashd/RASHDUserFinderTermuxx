#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
V4Z User Finder — original username & email OSINT checker.

Given a username, it checks whether a PUBLIC profile exists on a curated
list of platforms and prints the profile links. Given an email, it checks
the public Gravatar profile for that email and suggests a username search
from the address prefix.

Every site definition below (URL pattern + "account missing" fingerprints)
was written for this tool from scratch. It is NOT a copy of any existing
project, database or site list. Verdicts are three-state:
  FOUND     - a strong "profile exists" signal
  NOT FOUND - a strong "no such profile" signal
  UNKNOWN   - the site blocked us or answered ambiguously; verify manually

Pure Python standard library. No pip installs. Made for Termux.
Educational use only: check your own accounts or accounts you may check.
"""

import concurrent.futures
import hashlib
import json
import os
import re
import ssl
import sys
import time
import urllib.error
import urllib.parse
import urllib.request

VERSION = "1.1"
UA = ("Mozilla/5.0 (Linux; Android 13; Mobile) AppleWebKit/537.36 "
      "(KHTML, like Gecko) Chrome/124.0 Mobile Safari/537.36")
TIMEOUT = 10          # seconds per site
WORKERS = 18          # parallel checks

G = "\033[92m"; C = "\033[96m"; Y = "\033[93m"; R = "\033[91m"
DIM = "\033[90m"; B = "\033[1m"; X = "\033[0m"

# ---------------------------------------------------------------------------
# Site definitions.
#   n: display name          c: category
#   u: check URL ({u} = username, URL-quoted)
#   l: profile link shown to the user (defaults to u)
#   m: "missing" fingerprints in the page body (lowercase) -> NOT FOUND
#   f: "found" fingerprints in the page body (lowercase)   -> FOUND
#   t: trust a bare HTTP 200 as FOUND when no fingerprint matches
#   b: bot-challenge fingerprints ("checking your browser"...) -> UNKNOWN
#   cap: per-site body read cap in bytes (default 60000)
#   sub: username sits in the subdomain (DNS failure means NOT FOUND)
# ---------------------------------------------------------------------------
SITES = [
    # ---- Social -------------------------------------------------------
    dict(n="Facebook", c="Social", u="https://www.facebook.com/{u}",
         m=["this content isn't available", "this page isn't available"],
         f=[], t=False),
    dict(n="Instagram", c="Social", u="https://www.instagram.com/{u}/",
         m=["sorry, this page isn't available"],
         f=['"edge_followed_by"'], t=False),
    dict(n="X (Twitter)", c="Social", u="https://x.com/{u}",
         m=["this account doesn't exist", "this account doesn’t exist"],
         f=[], t=False),
    dict(n="TikTok", c="Social", u="https://www.tiktok.com/@{u}",
         m=['"statuscode":10221'],
         f=['"uniqueid":"'], t=False, cap=900000),
    dict(n="Telegram", c="Social", u="https://t.me/{u}",
         m=["if you have telegram, you can contact"],
         f=["tgme_page_title", "tgme_page_photo_image"], t=False),
    dict(n="Threads", c="Social", u="https://www.threads.net/@{u}",
         m=["sorry, this page isn't available"], f=[], t=False),
    dict(n="Snapchat", c="Social", u="https://www.snapchat.com/add/{u}",
         m=["content is not available", "this content is unavailable"],
         f=["snapcodeimageurl"], t=False),
    dict(n="Pinterest", c="Social", u="https://www.pinterest.com/{u}/",
         m=["user not found"], f=[], t=True, cap=1200000),
    dict(n="Reddit", c="Social",
         u="https://www.reddit.com/user/{u}/about.json",
         l="https://www.reddit.com/user/{u}",
         m=[], f=['"name":'], t=False),
    dict(n="Mastodon", c="Social", u="https://mastodon.social/@{u}",
         m=[], f=[], t=True),
    dict(n="Bluesky", c="Social",
         u="https://public.api.bsky.app/xrpc/app.bsky.actor.getProfile?actor={u}.bsky.social",
         l="https://bsky.app/profile/{u}.bsky.social",
         m=["profile not found", "invalid handle"], f=['"handle"'], t=False),
    dict(n="VK", c="Social", u="https://vk.com/{u}",
         m=["page not found", "страница не найдена"], f=[], t=False),
    dict(n="Tumblr", c="Social", u="https://{u}.tumblr.com",
         m=["there's nothing here", "there’s nothing here"],
         f=[], t=True, sub=True),

    # ---- Video --------------------------------------------------------
    dict(n="YouTube", c="Video", u="https://www.youtube.com/@{u}",
         m=["this page isn't available", "this page isn’t available"],
         f=[], t=True),
    dict(n="Twitch", c="Video", u="https://www.twitch.tv/{u}",
         m=["that content is unavailable", "channel is unavailable"],
         f=[" - twitch"], t=False),
    dict(n="Vimeo", c="Video", u="https://vimeo.com/{u}",
         m=[], f=[], t=True),
    dict(n="Dailymotion", c="Video", u="https://www.dailymotion.com/{u}",
         m=[], f=[], t=False),
    dict(n="Likee", c="Video", u="https://likee.video/@{u}",
         m=["not found"], f=[], t=False),

    # ---- Photo / Art --------------------------------------------------
    dict(n="Flickr", c="Photo", u="https://www.flickr.com/people/{u}",
         m=[], f=[], t=True),
    dict(n="Unsplash", c="Photo", u="https://unsplash.com/@{u}",
         m=[], f=[], t=True),
    dict(n="VSCO", c="Photo", u="https://vsco.co/{u}/gallery",
         m=[], f=[], t=True),
    dict(n="DeviantArt", c="Art", u="https://www.deviantart.com/{u}",
         m=[], f=[], t=True),
    dict(n="Behance", c="Art", u="https://www.behance.net/{u}",
         m=[], f=[], t=True),
    dict(n="Dribbble", c="Art", u="https://dribbble.com/{u}",
         m=[], f=[], t=True),
    dict(n="ArtStation", c="Art", u="https://www.artstation.com/{u}",
         m=[], f=[], t=True),
    dict(n="500px", c="Photo", u="https://500px.com/{u}",
         m=[], f=[], t=True),

    # ---- Music --------------------------------------------------------
    dict(n="SoundCloud", c="Music", u="https://soundcloud.com/{u}",
         m=[], f=[], t=True),
    dict(n="Spotify", c="Music", u="https://open.spotify.com/user/{u}",
         m=[], f=[], t=True),
    dict(n="Bandcamp", c="Music", u="https://{u}.bandcamp.com",
         m=[], f=[], t=True, sub=True),
    dict(n="Mixcloud", c="Music", u="https://www.mixcloud.com/{u}/",
         m=[], f=[], t=False),
    dict(n="Audiomack", c="Music", u="https://audiomack.com/{u}",
         m=[], f=[], t=False),
    dict(n="Last.fm", c="Music", u="https://www.last.fm/user/{u}",
         m=["not be found", "couldn't find"], f=[], t=True),
    dict(n="Audius", c="Music", u="https://audius.co/{u}",
         m=[], f=[], t=False),

    # ---- Gaming -------------------------------------------------------
    dict(n="Steam", c="Gaming", u="https://steamcommunity.com/id/{u}",
         m=["the specified profile could not be found"], f=[], t=True),
    dict(n="Chess.com", c="Gaming", u="https://www.chess.com/member/{u}",
         m=[], f=[], t=True),
    dict(n="Lichess", c="Gaming", u="https://lichess.org/api/user/{u}",
         l="https://lichess.org/@/{u}",
         m=["not found"], f=['"username"'], t=False),
    dict(n="Game Jolt", c="Gaming", u="https://gamejolt.com/@{u}",
         m=[], f=[], t=True),
    dict(n="itch.io", c="Gaming", u="https://{u}.itch.io",
         m=[], f=[], t=True, sub=True),
    dict(n="Newgrounds", c="Gaming", u="https://{u}.newgrounds.com",
         m=[], f=[], t=True, sub=True),
    dict(n="BoardGameGeek", c="Gaming", u="https://boardgamegeek.com/user/{u}",
         m=[], f=[], t=True),

    # ---- Developer ----------------------------------------------------
    dict(n="GitHub", c="Developer", u="https://github.com/{u}",
         m=[], f=[], t=True),
    dict(n="GitLab", c="Developer", u="https://gitlab.com/{u}",
         m=[], f=[], t=True),
    dict(n="Bitbucket", c="Developer", u="https://bitbucket.org/{u}",
         m=[], f=[], t=True),
    dict(n="Codeberg", c="Developer", u="https://codeberg.org/{u}",
         m=[], f=[], t=True),
    dict(n="SourceForge", c="Developer", u="https://sourceforge.net/u/{u}/",
         m=[], f=[], t=True),
    dict(n="Replit", c="Developer", u="https://replit.com/@{u}",
         m=[], f=[], t=True),
    dict(n="CodePen", c="Developer", u="https://codepen.io/{u}",
         m=[], f=[], t=True),
    dict(n="StackBlitz", c="Developer", u="https://stackblitz.com/@{u}",
         m=[], f=[], t=True),
    dict(n="Glitch", c="Developer", u="https://glitch.com/@{u}",
         m=[], f=[], t=True),
    dict(n="Observable", c="Developer", u="https://observablehq.com/@{u}",
         m=[], f=[], t=True),
    dict(n="JSFiddle", c="Developer", u="https://jsfiddle.net/user/{u}/",
         m=[], f=[], t=True),
    dict(n="HackerRank", c="Developer",
         u="https://www.hackerrank.com/rest/contests/master/hackers/{u}/profile",
         l="https://www.hackerrank.com/{u}",
         m=[], f=['"username"'], t=False),
    dict(n="LeetCode", c="Developer", u="https://leetcode.com/u/{u}/",
         m=[], f=[], t=True),
    dict(n="Codeforces", c="Developer", u="https://codeforces.com/profile/{u}",
         m=["user with handle", "not found"], f=[], t=True),
    dict(n="CodeChef", c="Developer", u="https://www.codechef.com/users/{u}",
         m=[], f=[], t=False),
    dict(n="AtCoder", c="Developer", u="https://atcoder.jp/users/{u}",
         m=[], f=[], t=True),
    dict(n="freeCodeCamp", c="Developer", u="https://www.freecodecamp.org/{u}",
         m=[], f=[], t=True),
    dict(n="Codecademy", c="Developer", u="https://www.codecademy.com/profiles/{u}",
         m=[], f=[], t=True),
    dict(n="Exercism", c="Developer", u="https://exercism.org/profiles/{u}",
         m=[], f=[], t=True),
    dict(n="Kaggle", c="Developer", u="https://www.kaggle.com/{u}",
         m=[], f=[], t=True, b=["checking your browser", "recaptcha"]),
    dict(n="Hacker News", c="Developer",
         u="https://news.ycombinator.com/user?id={u}",
         m=["no such user."], f=[], t=True),
    dict(n="Product Hunt", c="Developer", u="https://www.producthunt.com/@{u}",
         m=[], f=[], t=True),
    dict(n="Duolingo", c="Developer",
         u="https://www.duolingo.com/2017-06-30/users?username={u}",
         l="https://www.duolingo.com/profile/{u}",
         m=['"users":[]'], f=['"username"'], t=False),
    dict(n="TryHackMe", c="Developer", u="https://tryhackme.com/p/{u}",
         m=[], f=[], t=False),
    dict(n="Keybase", c="Developer", u="https://keybase.io/{u}",
         m=[], f=[], t=True),

    # ---- Writing / Reading --------------------------------------------
    dict(n="Medium", c="Writing", u="https://medium.com/@{u}",
         m=[], f=[], t=True),
    dict(n="Substack", c="Writing", u="https://{u}.substack.com",
         m=[], f=[], t=True, sub=True),
    dict(n="Wattpad", c="Writing", u="https://www.wattpad.com/user/{u}",
         m=[], f=[], t=True),
    dict(n="AO3", c="Writing", u="https://archiveofourown.org/users/{u}",
         m=[], f=[], t=True),
    dict(n="SlideShare", c="Writing", u="https://www.slideshare.net/{u}",
         m=[], f=[], t=True),
    dict(n="Quizlet", c="Writing", u="https://quizlet.com/{u}",
         m=[], f=[], t=True),
    dict(n="MyAnimeList", c="Writing", u="https://myanimelist.net/profile/{u}",
         m=[], f=[], t=True),
    dict(n="AniList", c="Writing", u="https://anilist.co/user/{u}",
         m=[], f=[], t=True),
    dict(n="Letterboxd", c="Writing", u="https://letterboxd.com/{u}",
         m=[], f=[], t=True),
    dict(n="Trakt", c="Writing", u="https://trakt.tv/users/{u}",
         m=[], f=[], t=True),
    dict(n="Untappd", c="Writing", u="https://untappd.com/user/{u}",
         m=[], f=[], t=True),

    # ---- Link pages ----------------------------------------------------
    dict(n="Linktree", c="Links", u="https://linktr.ee/{u}",
         m=[], f=[], t=True),
    dict(n="Beacons", c="Links", u="https://beacons.ai/{u}",
         m=[], f=[], t=True),
    dict(n="Carrd-like (bio.link)", c="Links", u="https://bio.link/{u}",
         m=[], f=[], t=True),
    dict(n="Solo.to", c="Links", u="https://solo.to/{u}",
         m=[], f=[], t=True),
    dict(n="AllMyLinks", c="Links", u="https://allmylinks.com/{u}",
         m=[], f=[], t=True),
    dict(n="Lnk.Bio", c="Links", u="https://lnk.bio/{u}",
         m=[], f=[], t=True),
    dict(n="Direct.me", c="Links", u="https://direct.me/{u}",
         m=[], f=[], t=True),
    dict(n="Campsite", c="Links", u="https://campsite.bio/{u}",
         m=[], f=[], t=True),
    dict(n="About.me", c="Links", u="https://about.me/{u}",
         m=[], f=[], t=True),

    # ---- Work / Money ---------------------------------------------------
    dict(n="Fiverr", c="Work", u="https://www.fiverr.com/{u}",
         m=[], f=[], t=True),
    dict(n="Freelancer", c="Work", u="https://www.freelancer.com/u/{u}",
         m=[], f=[], t=True),
    dict(n="Envato", c="Work", u="https://themeforest.net/user/{u}",
         m=[], f=[], t=True),
    dict(n="Etsy Shop", c="Work", u="https://www.etsy.com/shop/{u}",
         m=[], f=[], t=False),
    dict(n="eBay", c="Work", u="https://www.ebay.com/usr/{u}",
         m=[], f=[], t=True),
    dict(n="Patreon", c="Work", u="https://www.patreon.com/{u}",
         m=["page not found"], f=[], t=True),
    dict(n="Ko-fi", c="Work", u="https://ko-fi.com/{u}",
         m=[], f=[], t=True),
    dict(n="Buy Me a Coffee", c="Work", u="https://www.buymeacoffee.com/{u}",
         m=[], f=[], t=True),
    dict(n="Gumroad", c="Work", u="https://{u}.gumroad.com",
         m=[], f=[], t=True, sub=True),
    dict(n="Gravatar", c="Work", u="https://gravatar.com/{u}",
         m=[], f=[], t=True),

    # ---- More developer / creator ---------------------------------------
    dict(n="Hugging Face", c="Developer", u="https://huggingface.co/{u}",
         m=[], f=[], t=True),
    dict(n="Docker Hub", c="Developer", u="https://hub.docker.com/u/{u}",
         m=[], f=[], t=True),
    dict(n="npm", c="Developer", u="https://www.npmjs.com/~{u}",
         m=[], f=[], t=True),
    dict(n="PyPI", c="Developer", u="https://pypi.org/user/{u}/",
         m=[], f=[], t=True, b=["client challenge"]),
    dict(n="WordPress", c="Developer",
         u="https://profiles.wordpress.org/{u}/",
         m=[], f=[], t=True),
    dict(n="Archive.org", c="Writing", u="https://archive.org/details/@{u}",
         l="https://archive.org/details/@{u}",
         m=[], f=[], t=False),
    dict(n="OpenStreetMap", c="Writing",
         u="https://www.openstreetmap.org/user/{u}",
         m=[], f=[], t=True),
    # ---- Expansion pack ---------------------------------------------
    dict(n="Rumble", c="Video", u="https://rumble.com/user/{u}",
         m=[], f=[], t=True),
    dict(n="Kick", c="Video", u="https://kick.com/{u}",
         m=["channel not found"], f=[], t=False),
    dict(n="Odysee", c="Video", u="https://odysee.com/@{u}",
         m=[], f=[], t=False),
    dict(n="Trovo", c="Video", u="https://trovo.live/s/{u}",
         m=[], f=[], t=True),
    dict(n="YouNow", c="Video", u="https://www.younow.com/{u}",
         m=[], f=[], t=False),
    dict(n="Lemon8", c="Video", u="https://www.lemon8-app.com/@{u}",
         m=[], f=[], t=True),
    dict(n="Minds", c="Social", u="https://www.minds.com/{u}",
         m=[], f=[], t=False),
    dict(n="Plurk", c="Social", u="https://www.plurk.com/{u}",
         m=[], f=[], t=False),
    dict(n="CounterSocial", c="Social", u="https://counter.social/@{u}",
         m=[], f=[], t=False),
    dict(n="Gettr", c="Social", u="https://gettr.com/user/{u}",
         m=[], f=[], t=False),
    dict(n="Pixelfed", c="Social", u="https://pixelfed.social/{u}",
         m=[], f=[], t=True),
    dict(n="Clubhouse", c="Social", u="https://www.clubhouse.com/@{u}",
         m=[], f=[], t=True),
    dict(n="Micro.blog", c="Social", u="https://micro.blog/{u}",
         m=[], f=[], t=True),
    dict(n="Codewars", c="Developer", u="https://www.codewars.com/users/{u}",
         m=[], f=[], t=True),
    dict(n="HackerEarth", c="Developer", u="https://www.hackerearth.com/@{u}",
         m=[], f=[], t=True),
    dict(n="LightOJ", c="Developer", u="https://lightoj.com/user/{u}",
         m=[], f=[], t=True),
    dict(n="crates.io", c="Developer",
         u="https://crates.io/api/v1/users/{u}",
         l="https://crates.io/users/{u}",
         m=[], f=['"login"'], t=False),
    dict(n="RubyGems", c="Developer", u="https://rubygems.org/profiles/{u}",
         m=[], f=[], t=True),
    dict(n="NuGet", c="Developer", u="https://www.nuget.org/profiles/{u}",
         m=[], f=[], t=True),
    dict(n="Launchpad", c="Developer", u="https://launchpad.net/~{u}",
         m=[], f=[], t=True),
    dict(n="Packagist", c="Developer", u="https://packagist.org/users/{u}",
         m=[], f=[], t=True),
    dict(n="Hex", c="Developer", u="https://hex.pm/users/{u}",
         m=[], f=[], t=True),
    dict(n="Drupal", c="Developer", u="https://www.drupal.org/u/{u}",
         m=[], f=[], t=False, b=["client challenge"]),
    dict(n="CodeSandbox", c="Developer", u="https://codesandbox.io/u/{u}",
         m=[], f=[], t=False),
    dict(n="OpenHub", c="Developer", u="https://www.openhub.net/accounts/{u}",
         m=[], f=[], t=False),
    dict(n="SPOJ", c="Developer", u="https://www.spoj.com/users/{u}",
         m=[], f=[], t=False),
    dict(n="TopCoder", c="Developer", u="https://www.topcoder.com/members/{u}",
         m=[], f=[], t=False),
    dict(n="Anaconda", c="Developer", u="https://anaconda.org/{u}",
         m=["page not found"], f=[], t=False),
    dict(n="RuneScape", c="Gaming",
         u="https://secure.runescape.com/m=hiscore_oldschool/index_lite.ws?player={u}",
         l="https://secure.runescape.com/m=hiscore_oldschool/hiscorepersonal.ws?user1={u}",
         m=[], f=[], t=True),
    dict(n="osu!", c="Gaming", u="https://osu.ppy.sh/users/{u}",
         m=[], f=[], t=True),
    dict(n="GameBanana", c="Gaming", u="https://gamebanana.com/members/{u}",
         m=[], f=[], t=False),
    dict(n="HowLongToBeat", c="Gaming", u="https://howlongtobeat.com/user/{u}",
         m=[], f=[], t=True),
    dict(n="Speedrun", c="Gaming", u="https://www.speedrun.com/users/{u}",
         m=[], f=[], t=False),
    dict(n="PSNProfiles", c="Gaming", u="https://psnprofiles.com/{u}",
         m=[], f=[], t=False),
    dict(n="TrueAchievements", c="Gaming",
         u="https://www.trueachievements.com/gamer/{u}",
         m=[], f=[], t=False),
    dict(n="Nexus Mods", c="Gaming", u="https://www.nexusmods.com/profile/{u}",
         m=[], f=[], t=False),
    dict(n="CurseForge", c="Gaming", u="https://www.curseforge.com/members/{u}",
         m=[], f=[], t=False),
    dict(n="Backloggd", c="Gaming", u="https://backloggd.com/u/{u}",
         m=[], f=[], t=False),
    dict(n="ReverbNation", c="Music", u="https://www.reverbnation.com/{u}",
         m=[], f=[], t=True),
    dict(n="BandLab", c="Music", u="https://www.bandlab.com/{u}",
         m=[], f=[], t=False),
    dict(n="Hearthis", c="Music", u="https://hearthis.at/{u}",
         m=[], f=[], t=True),
    dict(n="Smule", c="Music", u="https://www.smule.com/{u}",
         m=["page not found"], f=[], t=False),
    dict(n="Genius", c="Music", u="https://genius.com/{u}",
         m=[], f=[], t=True),
    dict(n="Imgur", c="Photo", u="https://imgur.com/user/{u}",
         m=[], f=[], t=False),
    dict(n="Picsart", c="Photo", u="https://picsart.com/u/{u}",
         m=[], f=[], t=False),
    dict(n="ViewBug", c="Photo", u="https://www.viewbug.com/member/{u}",
         m=[], f=[], t=True),
    dict(n="Cara", c="Art", u="https://cara.app/{u}",
         m=[], f=[], t=False),
    dict(n="DEV.to", c="Writing", u="https://dev.to/{u}",
         m=[], f=[], t=True),
    dict(n="Hashnode", c="Writing", u="https://hashnode.com/@{u}",
         m=["user not found"], f=[], t=False),
    dict(n="Goodreads", c="Writing", u="https://www.goodreads.com/{u}",
         m=[], f=[], t=False),
    dict(n="WriteAs", c="Writing", u="https://write.as/{u}",
         m=[], f=[], t=True),
    dict(n="StoryGraph", c="Writing",
         u="https://app.thestorygraph.com/profile/{u}",
         m=[], f=[], t=False),
    dict(n="Inkitt", c="Writing", u="https://www.inkitt.com/{u}",
         m=[], f=[], t=False),
    dict(n="Quotev", c="Writing", u="https://www.quotev.com/{u}",
         m=[], f=[], t=False),
    dict(n="Snipfeed", c="Links", u="https://snipfeed.co/{u}",
         m=[], f=[], t=True),
    dict(n="Milkshake", c="Links", u="https://msha.ke/{u}",
         m=[], f=[], t=True),
    dict(n="Flowpage", c="Links", u="https://www.flowpage.com/{u}",
         m=[], f=[], t=True),
    dict(n="Taplink", c="Links", u="https://taplink.cc/{u}",
         m=[], f=[], t=False),
    dict(n="Guru", c="Work", u="https://www.guru.com/freelancers/{u}",
         m=[], f=[], t=True),
    dict(n="PeoplePerHour", c="Work",
         u="https://www.peopleperhour.com/freelancer/{u}",
         m=[], f=[], t=True),
    dict(n="Codementor", c="Work", u="https://www.codementor.io/@{u}",
         m=[], f=[], t=True),
    dict(n="Wellfound", c="Work", u="https://wellfound.com/u/{u}",
         m=[], f=[], t=True),
    dict(n="Contra", c="Work", u="https://contra.com/{u}",
         m=[], f=[], t=True),
    dict(n="99designs", c="Work", u="https://99designs.com/profiles/{u}",
         m=[], f=[], t=True),
    dict(n="Malt", c="Work", u="https://www.malt.com/profile/{u}",
         m=[], f=[], t=False),
    dict(n="Upwork", c="Work", u="https://www.upwork.com/freelancers/{u}",
         m=[], f=[], t=False),
]

BLOCKED_STATUS = (401, 403, 406, 429, 999)


def fetch(url, site):
    """Return (status, lowercase_body_sample, error_kind)."""
    req = urllib.request.Request(url, headers={
        "User-Agent": UA,
        "Accept": "text/html,application/json,*/*",
        "Accept-Language": "en-US,en;q=0.9",
    })
    ctx = ssl.create_default_context()
    try:
        with urllib.request.urlopen(req, timeout=TIMEOUT, context=ctx) as r:
            raw = r.read(site.get("cap", 60000))
            return r.status, raw.decode("utf-8", "replace").lower(), ""
    except urllib.error.HTTPError as e:
        try:
            raw = e.read(60000)
            text = raw.decode("utf-8", "replace").lower()
        except Exception:
            text = ""
        return e.code, text, ""
    except urllib.error.URLError as e:
        reason = str(getattr(e, "reason", e)).lower()
        if "name or service not known" in reason or "getaddrinfo" in reason \
                or "name resolution" in reason:
            return 0, "", "dns"
        if "certificate" in reason or "ssl" in reason:
            return 0, "", "ssl"
        return 0, "", "net"
    except Exception:
        return 0, "", "net"


def check_site(site, username):
    q = urllib.parse.quote(username, safe="._-")
    url = site["u"].format(u=q)
    link = (site.get("l") or site["u"]).format(u=q)
    status, body, err = fetch(url, site)
    if err == "ssl":
        # one retry without certificate verification (some networks MITM)
        try:
            req = urllib.request.Request(url, headers={"User-Agent": UA})
            with urllib.request.urlopen(
                    req, timeout=TIMEOUT,
                    context=ssl._create_unverified_context()) as r:
                body = r.read(site.get("cap", 60000)).decode("utf-8", "replace").lower()
                status = r.status
                err = ""
        except Exception:
            pass
    if err == "dns" and site.get("sub"):
        return dict(name=site["n"], cat=site["c"], url=link, verdict="NOT FOUND")
    if err:
        return dict(name=site["n"], cat=site["c"], url=link, verdict="UNKNOWN")
    low = (body or "").lower()
    for marker in site.get("b", []):
        if marker.lower() in low:
            return dict(name=site["n"], cat=site["c"], url=link,
                        verdict="UNKNOWN")
    for marker in site.get("m", []):
        if marker.lower() in low:
            return dict(name=site["n"], cat=site["c"], url=link,
                        verdict="NOT FOUND")
    for marker in site.get("f", []):
        if marker.lower() in low:
            return dict(name=site["n"], cat=site["c"], url=link,
                        verdict="FOUND")
    if status in (404, 410):
        return dict(name=site["n"], cat=site["c"], url=link,
                    verdict="NOT FOUND")
    if status in BLOCKED_STATUS:
        return dict(name=site["n"], cat=site["c"], url=link,
                    verdict="UNKNOWN")
    if status == 200:
        return dict(name=site["n"], cat=site["c"], url=link,
                    verdict="FOUND" if site.get("t") else "UNKNOWN")
    if status in (301, 302, 303, 307, 308):
        return dict(name=site["n"], cat=site["c"], url=link,
                    verdict="UNKNOWN")
    return dict(name=site["n"], cat=site["c"], url=link, verdict="UNKNOWN")


def search_username(username, save=False):
    username = username.strip()
    if not re.match(r"^[A-Za-z0-9._\-]{2,40}$", username):
        print(R + "  Invalid username. Use 2-40 letters, numbers, . _ -" + X)
        return None
    total = len(SITES)
    print("\n" + C + f"  Searching '{username}' on {total} platforms..." + X)
    results, done = [], 0
    with concurrent.futures.ThreadPoolExecutor(max_workers=WORKERS) as ex:
        futures = {ex.submit(check_site, s, username): s for s in SITES}
        for fut in concurrent.futures.as_completed(futures):
            done += 1
            try:
                results.append(fut.result())
            except Exception:
                s = futures[fut]
                results.append(dict(name=s["n"], cat=s["c"],
                                    url=s["u"], verdict="UNKNOWN"))
            sys.stdout.write(f"\r  ⏳ {done}/{total} checked")
            sys.stdout.flush()
    print("\r" + " " * 40 + "\r", end="")
    found = [r for r in results if r["verdict"] == "FOUND"]
    unknown = [r for r in results if r["verdict"] == "UNKNOWN"]
    notfound = [r for r in results if r["verdict"] == "NOT FOUND"]
    order = {"Video": 0, "Social": 1, "Developer": 2, "Gaming": 3,
             "Music": 4, "Photo": 5, "Art": 6, "Writing": 7, "Links": 8,
             "Work": 9}
    found.sort(key=lambda r: (order.get(r["cat"], 9), r["name"]))
    print(B + G + f"  ✅ FOUND ({len(found)})" + X)
    if found:
        for r in found:
            print(f"   {G}✔{X} {r['name']:<16} {C}{r['url']}{X}")
    else:
        print("   (none confirmed)")
    print(B + Y + f"\n  ❓ UNKNOWN - blocked/unclear, verify manually ({len(unknown)})" + X)
    if unknown:
        for r in sorted(unknown, key=lambda r: r["name"]):
            print(f"   {Y}?{X} {r['name']:<16} {DIM}{r['url']}{X}")
    else:
        print("   (none)")
    print(DIM + f"\n  ❌ Not found on {len(notfound)} platforms" + X)
    if save:
        save_report(username, results)
    return results


def save_report(username, results):
    folder = os.path.expanduser("~/v4zfind-reports")
    os.makedirs(folder, exist_ok=True)
    stamp = time.strftime("%Y%m%d-%H%M%S")
    base = os.path.join(folder, f"{username}_{stamp}")
    with open(base + ".json", "w", encoding="utf-8") as fh:
        json.dump(dict(username=username, tool="V4Z User Finder",
                       version=VERSION, when=stamp, results=results),
                  fh, ensure_ascii=False, indent=2)
    with open(base + ".txt", "w", encoding="utf-8") as fh:
        fh.write(f"V4Z User Finder report — {username} ({stamp})\n")
        fh.write("=" * 56 + "\n")
        for verdict in ("FOUND", "UNKNOWN", "NOT FOUND"):
            fh.write(f"\n{verdict}:\n")
            for r in results:
                if r["verdict"] == verdict:
                    fh.write(f"  {r['name']:<16} {r['url']}\n")
    print(G + f"\n  💾 Report saved: {base}.txt / .json" + X)
    print(DIM + "  (reports live in ~/v4zfind-reports)" + X)


def check_email(email):
    email = email.strip().lower()
    if not re.match(r"^[^@\s]+@[^@\s]+\.[^@\s]+$", email):
        print(R + "  That does not look like an email address." + X)
        return
    print("\n" + C + f"  Checking public profiles for {email}..." + X)
    digest = hashlib.md5(email.encode("utf-8")).hexdigest()
    url = f"https://www.gravatar.com/{digest}.json"
    status, body, err = fetch(url, {})
    if status == 200 and body:
        try:
            entry = json.loads(body)["entry"][0]
        except Exception:
            entry = None
        if entry:
            print(B + G + "  ✅ Gravatar public profile FOUND" + X)
            name = entry.get("displayName") or entry.get("preferredUsername")
            if name:
                print(f"   Name     : {name}")
            if entry.get("currentLocation"):
                print(f"   Location : {entry['currentLocation']}")
            if entry.get("aboutMe"):
                about = str(entry["aboutMe"]).replace("\n", " ")[:200]
                print(f"   About    : {about}")
            accounts = entry.get("accounts") or []
            for acc in accounts[:8]:
                print(f"   {acc.get('shortname', '?'):<14} {C}{acc.get('url', '')}{X}")
            print(f"   Profile  : {C}https://gravatar.com/{digest}{X}")
        else:
            print(Y + "  Gravatar answered, but no usable profile data." + X)
    elif status == 404:
        print(Y + "  ❌ No public Gravatar profile for this email." + X)
    else:
        print(Y + f"  ❓ Gravatar check unclear (status {status}). Try again later." + X)
    prefix = email.split("@")[0]
    print(DIM + f"\n  Tip: people often reuse the same name everywhere."
                f" Run:  v4zfind --user {prefix}" + X)


BANNER = r"""
__     __  _  _   ______
\ \   / / | || | |__  /
 \ \ / /  | || |_  / /
  \ V /   |__   _|/ /_
   \_/       |_| /____|

  V4Z USER FINDER  —  by V4Z RASHD
  Username & email public-profile checker
"""


def menu():
    while True:
        print(BANNER)
        print("  1) 🔍 Search by username")
        print("  2) ✉️  Search by email (public profile only)")
        print("  3) ❌ Exit")
        choice = input("\n  Choose: ").strip()
        if choice == "1":
            name = input("  Username: ").strip()
            if name:
                ans = input("  Save report? (y/N): ").strip().lower()
                search_username(name, save=(ans == "y"))
            input("\n  Press Enter to continue...")
        elif choice == "2":
            mail = input("  Email: ").strip()
            if mail:
                check_email(mail)
            input("\n  Press Enter to continue...")
        elif choice == "3":
            print("  Bye. Stay legal, stay curious. — V4Z RASHD")
            break
        else:
            print(R + "  Pick 1, 2 or 3." + X)


def main(argv):
    if len(argv) < 2:
        menu()
        return 0
    args = argv[1:]
    save = "--save" in args
    if args[0] in ("-h", "--help"):
        print("Usage:")
        print("  v4zfind                      interactive menu")
        print("  v4zfind --user NAME [--save] search a username on 100+ sites")
        print("  v4zfind --email ADDRESS      check public Gravatar profile")
        return 0
    if args[0] == "--user" and len(args) >= 2:
        search_username(args[1], save=save)
        return 0
    if args[0] == "--email" and len(args) >= 2:
        check_email(args[1])
        return 0
    print(R + "  Unknown option. Run: v4zfind --help" + X)
    return 1


if __name__ == "__main__":
    try:
        sys.exit(main(sys.argv))
    except KeyboardInterrupt:
        print("\n  Stopped.")
        sys.exit(130)
