// =======================
// SANITIZE (XSS SAFE)
// =======================
function sanitize(string) {
    if (!string) return '';
    const map = {
        '&': '&amp;',
        '<': '&lt;',
        '>': '&gt;',
        '"': '&quot;',
        "'": '&#x27;',
        "/": '&#x2F;',
    };
    return String(string).replace(/[&<>"'/]/g, m => map[m]);
}

// =======================
// ERROR
// =======================
function show_error(msg){
    const error_html = `
    <div id="error" class="error">
        <div class="error_head">
          <img src="../images/error.svg" class="error_img">
          <span class="error_header">ERROR</span>
        </div>
        <div class="error_body">
          <span class="error_bodytxt">${sanitize(msg)}</span>
        </div>
    </div>
    `;
    wpintel_debug('triggered show_error function');
    document.getElementById('container').innerHTML = error_html;
}

// =======================
// SUCCESS
// =======================
function show_success(msg){
    const success_html = `
    <div id="success" class="success">
        <div class="success_head">
            <img src="../images/success_img.svg" class="success_img">
            <span class="success_header">SUCCESS</span>
        </div>
        <div class="success_body">
            <span class="success_bodytxt">${msg}</span>
        </div>
    </div>
    `;
    wpintel_debug('triggered the show_success function');
    document.getElementById('container').innerHTML = success_html;
}

// =======================
// SCANNING
// =======================
function show_scanning(simage, sname, sstage){
    const prepared = `
    <div class="wp_check">
        <img class="wp_chk_stat" src="${simage}">
        <h1>${sanitize(sname)}</h1>
    </div>`;
    wpintel_debug('Scanning WP: ' + sname);
    document.getElementById('container').innerHTML = prepared;
}

// =======================
// DONATE
// =======================
function donate(){
    wpintel_debug('triggered donate');
    const dhtml = `
    <div class="donate_div">
        <h2>DONATE!</h2>
        <h4>If you want to support development, feel free to donate or reach out.</h4>
        <img src="../images/qr.png"><br>
        Bitcoin Address: <b>14GpkQAEwgfnpLat2exTe8XhogHnf5NSGr</b>
    </div>
    `;
    document.getElementById('container').innerHTML = dhtml;
}

// =======================
// WP NOT FOUND
// =======================
function wordpress_not_found(){
    const cnt = `
    <div class="wpnf">
        <center>
            <img src="../images/wordpress_fail.svg" style="width:156px;filter:drop-shadow(3px 4px 1px #ff3b00)">
        </center>
        <div class="inline_error">Couldn't detect any WordPress installation on this website!</div>
    </div>`;
    document.getElementById('container').innerHTML = cnt;
}

// =======================
// WP FOUND
// =======================
function wordpress_fond(){
    const html = `
    <div id="wordpress_found">
        <div style="text-align:center;">
            <div class="wordpress_found">
                <h1 class="wp_found_h1">WordPress Detected!</h1>
            </div>
            <button id="version_scan" class="reg_scan">Version & Vulnerabilities</button>
            <button id="theme_scan" class="reg_scan">Themes & Plugins Information</button>
            <button id="user_scan" class="reg_scan">Enumerate Usernames</button>
            <button id="reg_scan" class="reg_scan">Check for User Registration</button>
            <button id="path_scan" class="reg_scan">Check for Path Disclosure</button>
        </div>
    </div>
    `;

    document.getElementById('ret_menu').style.display = 'block';
    document.getElementById('container').innerHTML = html;

    document.querySelectorAll('button').forEach(btn => {
        btn.addEventListener('click', trackButtonClick);
    });
}

// =======================
// THEMES & PLUGINS
// =======================
function show_themes_and_plugins(url, themes, plugins){
    let contents = `
    <div class="tp_head">
        <div class="tp_theme">Themes: <span>${themes.length}</span></div>
        <div class="tp_plugin">Plugins: <span>${plugins.length}</span></div>
    </div>`;

    // THEMES
    if (themes.length > 0){
        contents += `<table class="themes_table">
            <tr><th>Theme</th><th>Link</th></tr>`;

        themes.forEach(theme => {
            const safe = sanitize(theme);
            contents += `
            <tr>
                <td>${safe}</td>
                <td><a href="${url}/wp-content/themes/${safe}" target="_blank">${safe}</a></td>
            </tr>`;
        });

        contents += '</table>';
    } else {
        contents += '<div class="inline_error">No Themes detected</div>';
    }

    // PLUGINS
    if (plugins.length > 0){
        contents += `<table class="plugins_table">
            <tr><th>Plugin</th><th>Link</th></tr>`;

        plugins.forEach(plugin => {
            const safe = sanitize(plugin);
            contents += `
            <tr>
                <td>${safe}</td>
                <td><a href="${url}/wp-content/plugins/${safe}" target="_blank">${safe}</a></td>
            </tr>`;
        });

        contents += '</table>';
    } else {
        contents += '<div class="inline_error">No Plugins detected</div>';
    }

    document.getElementById('container').innerHTML = contents;
}

// =======================
// USERS
// =======================
function show_users(userarray){
    let contents = `<div class="users_detected">Usernames Enumerated: ${userarray.length}</div>`;
    contents += `<table class="plugins_table">
        <tr><th>Display Name</th><th>Username</th></tr>`;

    userarray.forEach(u => {
        if (u !== '||'){
            const [slug, display] = u.split('||');
            contents += `
            <tr>
                <td>${sanitize(display)}</td>
                <td>${sanitize(slug)}</td>
            </tr>`;
        }
    });

    contents += '</table>';
    document.getElementById('container').innerHTML = contents;
}

// =======================
// VERSION + VULNS
// =======================
async function show_version(version, vulns){
    try {
        const res = await fetch('https://api.wordpress.org/core/version-check/1.7/');
        const json = await res.json();
        const latest_version = json?.offers?.[0]?.version;

        let content = `<div class="wp_ver_info">
            <div class="cur_ver">Version : ${sanitize(version)}</div>`;

        if (version === latest_version){
            content += '<div class="latest_ver ver_badge">✔ Latest</div>';
        } else {
            content += '<div class="outdated_ver ver_badge">✖ Outdated</div>';
        }

        if (!vulns){
            content += '<div class="inline_error">Error fetching vulnerabilities</div></div>';
            document.getElementById('container').innerHTML = content;
            return;
        }

        let parsed;
        try {
            parsed = JSON.parse(vulns);
        } catch {
            content += '<div class="inline_error">Invalid vulnerability data</div></div>';
            document.getElementById('container').innerHTML = content;
            return;
        }

        const wpvulns = parsed.vulnerabilities || [];

        content += `<div class="outdated_ver ver_badge">${wpvulns.length} vulns</div></div>`;

        if (wpvulns.length > 0){
            content += `<table class="plugins_table">
                <tr><th>Vulnerability</th></tr>`;

            wpvulns.forEach(v => {
                content += `<tr><td>${sanitize(v.name)}</td></tr>`;
            });

            content += '</table>';
        }

        document.getElementById('container').innerHTML = content;

    } catch (err) {
        wpintel_debug(err);
        show_error('Failed to load version info');
    }
}

// =======================
// NEW: COMPONENT VULNS UI
// =======================
function show_components_vuln(vulnData){
    if (!vulnData || vulnData.length === 0) return;

    let content = `<div class="tp_head"><h2>Component Vulnerabilities</h2></div>`;

    vulnData.forEach(raw => {
        try {
            const parsed = JSON.parse(raw);
            const vulns = parsed.vulnerabilities || [];

            if (vulns.length > 0){
                content += `<table class="plugins_table">
                    <tr><th>Vulnerability</th></tr>`;

                vulns.forEach(v => {
                    content += `<tr><td>${sanitize(v.name)}</td></tr>`;
                });

                content += '</table>';
            }
        } catch {}
    });

    document.getElementById('container').innerHTML += content;
}

// =======================
// RELOAD
// =======================
function show_reload(){
    const content = `
    <div class="reload_div">
        <img src="../images/broken-heart.svg" class="broken-heart">
        <h1>Oops!</h1>
        <h4>Something went wrong, please reload.</h4>
        <button class="reload_but" onclick="location.reload()">
            <img src="../images/refresh.png" class="reload_img"> Reload
        </button>
    </div>`;
    document.getElementById('container').innerHTML = content;
}
