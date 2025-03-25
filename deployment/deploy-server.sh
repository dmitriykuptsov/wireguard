echo "Updating the system"
sudo apt-get update
echo "Installing libraries"
sudo pip3 install pycryptodome
echo "Preparing directories"
mkdir /opt/wg/
cd ..
echo "Copying the files"
rsync -rv  config crypto network packets routing states tools utils wg.py /opt/wg/
echo "Copying the service file"
cd startup
cp wg.service /etc/systemd/system/
sudo systemctl enable wg
sudo systemctl start wg