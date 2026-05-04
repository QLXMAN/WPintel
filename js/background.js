// helper: fetch with timeout
function fetchWithTimeout(url, timeout = 8000) {
    return Promise.race([
        fetch(url),
        new Promise((_, reject) =>
            setTimeout(() => reject(new Error('Timeout')), timeout)
        )
    ]);
}

// =======================
// PATH CHECK
// =======================
async function check_path(url) {
    show_scanning('../images/gathering.svg', 'Looking for Path Disclosure..', '8');
    const rss_url = `${url}/wp-includes/rss.php`;

    try {
        const response = await fetchWithTimeout(rss_url);
        const content = await response.text();

        const match = content.match(/<b>\/(.*?)wp-includes\/rss.php<\/b/);

        if (match) {
            const path = '/' + match[1];
            wpintel_debug('Path detected: ' + path);
            show_success(path);
            return true;
        }

        throw new Error('No match found');

    } catch (err) {
        wpintel_debug('Error getting path: ' + err);
        show_error('path not detected!');
        return false;
    }
}

// =======================
// USER ENUMERATION
// =======================
async function check_users(url) {
    show_scanning('../images/users.svg', 'Acquiring Usernames...', '7');

    const json_url = `${url}/wp-json/wp/v2/users`;
    window.wordpress_users = [];

    try {
        const response = await fetchWithTimeout(json_url);

        if (!response.ok) throw new Error(`HTTP ${response.status}`);

        const json = await response.json();

        json.forEach(userObj => {
            if (userObj.slug) {
                const user = `${userObj.slug}||${userObj.name || ''}`;
                wpintel_debug('Enumerated username: ' + userObj.slug);
                window.wordpress_users.push(user);
            }
        });

        if (window.wordpress_users.length > 0) {
            show_users(window.wordpress_users);
            return true;
        }

        throw new Error('No users found');

    } catch (err) {
        wpintel_debug('User enumeration failed: ' + err);
        show_error('No usernames could be enumerated!');
        return false;
    }
}

// =======================
// REGISTRATION CHECK
// =======================
async function check_reg(url) {
    show_scanning('../images/reg.svg', 'Probing User Registration...', '5');

    const reg_url = `${url}/wp-login.php?action=register`;
    wpintel_debug('Registration URL: ' + reg_url);

    try {
        const res = await fetchWithTimeout(reg_url);
        const source = await res.text();

        const doc = new DOMParser().parseFromString(source, "text/html");

        if (
            doc.querySelector('form') &&
            (
                source.includes('Registration confirmation will be emailed') ||
                doc.querySelector('#user_email') ||
                source.includes('value="Register"')
            )
        ) {
            const reg_ahref = `<a href="${reg_url}" class="reg_button">REGISTER HERE</a>`;
            show_success('User registration is <b>enabled</b> in this site.<br><br>' + reg_ahref);
            return true;
        }

        throw new Error('Registration disabled');

    } catch (err) {
        wpintel_debug(err);
        show_error('User registration disabled!');
        return false;
    }
}

// =======================
// THEMES & PLUGINS
// =======================
async function check_theme(alllinks, parsed_source) {
    show_scanning('../images/themes.svg', 'Getting Theme Information...', '2');

    window.wordpress_themes = [];
    window.wordpress_plugins = [];

    const themes = new Set();
    const plugins = new Set();

    for (let href of alllinks) {
        try {
            if (/wp-content\/themes/.test(href)) {
                const match = href.match(/wp-content\/themes\/(.*?)\//);
                if (match) themes.add(match[1]);
            }

            if (/wp-content\/plugins/.test(href)) {
                const match = href.match(/wp-content\/plugins\/(.*?)\//);
                if (match) plugins.add(match[1]);
            }
        } catch (err) {
            wpintel_debug(err);
        }
    }

    window.wordpress_themes = [...themes];
    window.wordpress_plugins = [...plugins];

    if (themes.size || plugins.size) {
        show_themes_and_plugins(window.targeturl, window.wordpress_themes, window.wordpress_plugins);

        // 🔥 NEW: check vulnerabilities for themes & plugins
        await check_components_vuln(window.wordpress_themes, window.wordpress_plugins);

        return true;
    }

    show_error('WPintel could not detect any themes or plugins');
    return false;
}

// =======================
// COMPONENT VULN CHECK
// =======================
async function check_components_vuln(themes, plugins) {
    show_scanning('../images/crawl_vuln.svg', 'Checking Theme & Plugin Vulnerabilities...', '3');

    const requests = [];

    // plugins
    plugins.forEach(plugin => {
        const url = `https://www.wpvulnerability.net/plugin/${plugin}/`;
        requests.push(fetchWithTimeout(url).then(r => r.ok ? r.text() : null));
    });

    // themes
    themes.forEach(theme => {
        const url = `https://www.wpvulnerability.net/theme/${theme}/`;
        requests.push(fetchWithTimeout(url).then(r => r.ok ? r.text() : null));
    });

    try {
        const results = await Promise.allSettled(requests);

        const vulnData = [];

        results.forEach((res, index) => {
            if (res.status === 'fulfilled' && res.value) {
                vulnData.push(res.value);
            }
        });

        // send all collected data to UI
        show_components_vuln(vulnData);

    } catch (err) {
        wpintel_debug('Component vuln check failed: ' + err);
    }
}

// =======================
// VERSION HELPERS
// =======================
function fetch_version_from_generator(parsed_source) {
    try {
        const meta = parsed_source.querySelector("meta[name='generator']");
        if (!meta) return;

        const content = meta.getAttribute("content");
        if (/WordPress/.test(content)) {
            return content.match(/WordPress (.*)/)?.[1];
        }
    } catch {}
}

function fetch_version_from_emoji(source_string) {
    const match = source_string.match(/wp-emoji-release\.min\.js\?ver=(.*?)"/);
    return match ? match[1] : undefined;
}

async function fetch_version_from_feed(url) {
    try {
        const res = await fetchWithTimeout(`${url}/feed/`);
        const source = await res.text();
        return source.match(/<generator>https:\/\/wordpress.org\/\?v=(.*?)<\/generator>/)?.[1];
    } catch {}
}

async function fetch_version_from_atom(url) {
    try {
        const res = await fetchWithTimeout(`${url}/feed/atom`);
        const source = await res.text();
        return source.match(/version="(.*?)">WordPress/)?.[1];
    } catch {}
}

async function fetch_version_from_opml(url) {
    try {
        const res = await fetchWithTimeout(`${url}/wp-links-opml.php`);
        const source = await res.text();
        return source.match(/generator="WordPress\/(.*?)"/)?.[1];
    } catch {}
}

// =======================
// VERSION CHECK
// =======================
async function check_version(source_string, parsed_source, url) {
    show_scanning('../images/version.svg', 'Getting WordPress Version...', '1');

    window.wordpress_version = '0';

    let version =
        fetch_version_from_generator(parsed_source) ||
        fetch_version_from_emoji(source_string);

    if (!version) {
        const results = await Promise.allSettled([
            fetch_version_from_feed(url),
            fetch_version_from_atom(url),
            fetch_version_from_opml(url)
        ]);

        version = results.find(r => r.status === 'fulfilled' && r.value)?.value;
    }

    if (!version) {
        show_error('<b>Oops!!!</b><br>WordPress version could not be detected!');
        return;
    }

    window.wordpress_version = version;
    wpintel_debug('Version: ' + window.wordpress_version + ' detected');

    await check_vuln(version);
}

// =======================
// CORE VULN CHECK
// =======================
async function check_vuln(version) {
    show_scanning('../images/crawl_vuln.svg', 'Checking for Version Vulnerabilities...', '4');

    const vuln_url = `https://www.wpvulnerability.net/core/${version}/`;
    wpintel_debug('wpvuln url: ' + vuln_url);

    try {
        const res = await fetchWithTimeout(vuln_url);

        if (!res.ok) throw new Error('No vuln data');

        const source = await res.text();
        show_version(version, source);

    } catch (err) {
        wpintel_debug(err);
        show_version(version, false);
    }
}
