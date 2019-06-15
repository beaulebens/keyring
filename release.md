This is a WordPress plugin, hosted primarily on GitHub. To ship a release to the plugin directory, follow these steps;

1. Make sure the changelog in `readme.txt` is fully up to date (review commit history since last release if needed, there's a link on GitHub's releases page to do that, next to each release; https://github.com/beaulebens/keyring/releases)
2. Update version numbers;
    - `readme.txt` (`Stable Tag:`, Chanegelog latest entry)
    - `keyring.php` (`Version:`, `KEYRING__VERSION`)
3. Update the `Tested up to:` header in `readme.txt` to the latest version of WordPress.
4. Stage, commit, push everything up to GitHub.
5. Create a new release at https://github.com/beaulebens/keyring/releases/new
    - Version should be in the form `vX.Y.Z`, targeted to `master`.
    - Provide some details of the changes (usually just copy the changelog)
6. Check out the entire SVN repo from WP.org (`svn co http://plugins.svn.wordpress.org/keyring`)
7. Copy the latest plugin files (from the GitHub copy) into `/trunk` of the SVN checkout (you can just drag/drop from Finder, and it'll ignore all the `.git` files).
8. Reconcile the status of the SVN checkout. Run `svn stat` and then `svn add` or whatever you need to do to get it all in order.
9. Copy `trunk` to a tag matching the version number using `svn cp trunk/ tags/X.Y.Z` (no leading `v` on the version number here!)
10. Now commit and push to the WP.org directory using `svn ci` (with a message like "Tagging vX.Y.Z" when prompted)
11. Verify that the new version is showing up at https://wordpress.org/plugins/keyring/ (can take a few minutes)