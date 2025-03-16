set -e

root_dir=$PWD
find . -type f \( -name "*pirogue-admin*.buildinfo" -o -name "*pirogue-admin*.changes" -o -name "*pirogue-admin*.deb" \) -exec rm {} \;

# Build the API
cd pirogue-admin-api/src/python
dpkg-buildpackage -b -tc -uc -us -ui
mv ../python3-pirogue-admin-api_*.deb "$root_dir"
cd "$root_dir"

# Required by the the other 2 packages
sudo apt install -y ./python3-pirogue-admin-api_*.deb

# Build the admin daemon
cd pirogue-admin
dpkg-buildpackage -b -tc -uc -us -ui
cd "$root_dir"

# Build the admin client
cd pirogue-admin-client
dpkg-buildpackage -b -tc -uc -us -ui
cd "$root_dir"

# Clean buildinfo and changes
cd "$root_dir"
sudo apt purge -y python3-pirogue-admin-api
find . -type f \( -name "*pirogue-admin*.buildinfo" -o -name "*pirogue-admin*.changes" \) -exec rm {} \;
