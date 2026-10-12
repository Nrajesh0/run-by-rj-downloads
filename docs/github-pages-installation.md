# Install and update RuN by Rj on Fedora

1. Visit https://nrajesh0.github.io/run-by-rj-downloads/.
2. Click **Install on Fedora**. Download the `.flatpakref` file if your browser
   asks, then open it in Fedora Software.
3. Confirm the installation and adding the RuN update source. Fedora Software
   may also download the GNOME runtime from Flathub.
4. Start **RuN by Rj (Development)** from your app menu.

Once installed from this source, use Fedora Software's Updates page for later
versions. Its update settings decide whether updates happen automatically.
A newly published version can take time to appear in Software.

Terminal alternative:

```sh
flatpak install --user https://nrajesh0.github.io/run-by-rj-downloads/run-by-rj.flatpakref
flatpak update --user io.github.nrajesh0.RunByRj
```

Back up your notes before updating. The app remains a development build; full
installed recovery, upgrade and rollback testing is pending.

## Already installed a local development package?

The old local development remote will not automatically turn into this online
update source. First identify your installation and its origin:

```sh
flatpak list --app --columns=application,branch,origin,installation
```

The app ID is `io.github.nrajesh0.RunByRj`, branch `development-security-v2`.
For a user installation, add the official remote and change the origin:

```sh
flatpak remote-add --user --if-not-exists run-by-rj https://nrajesh0.github.io/run-by-rj-downloads/run-by-rj.flatpakrepo
flatpak install --user --reinstall run-by-rj io.github.nrajesh0.RunByRj//development-security-v2
```

If the existing app is a system installation, use `--system` instead of `--user`
for both commands. Do not install a second copy unintentionally. These commands
keep the same development branch and profile paths; do not use `--delete-data`.
The website displays the publisher's public signing fingerprint. Normal releases
retain that signing key. If a remote with this name already exists, check its
URL with `flatpak remote-info`/`flatpak remotes --show-details` before proceeding;
`--if-not-exists` does not change an existing remote.
