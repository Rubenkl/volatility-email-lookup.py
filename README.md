# Process E-mail Grabber
## About
Developed by Ruben Kluge for the Memory Forensics course at LSU.
*ps_email_lookup.py*

## Why use this plugin?
This plugin can be used to determine e-mail age, by matching it to the database of [HaveIBeenPwned](https://haveibeenpwned.com/).
This can be useful, as some malware could send details of keyloggers, etc. to a particular e-mail. Indications of no breaches could possibly determine the usage of an e-mail address.

## Usage
1.  Unpack the ZIP file and put the .py files in a directory.
    
2.  install the python dependency ratelimit via the commandline using pip:  
    `pip install ratelimit  `
    or in case of the Vagrant box use sudo:  
   `sudo pip install ratelimit`
    
3.  Specify the plugin directory with `--plugin=[PATH]`
    
4.  Install your volatility profiles for your system you want to analyze (download into:  
    `/volatility/plu‌​gins/overlays/linux)`
    
5.  Run it with the optional parameters `-p [process]` and `-D [dump directory]`

Example:
```bash
python vol.py --plugins=/vagrant/plugin  --profile=LinuxXubuntu1404x64 -f /vagrant/NILES.lime ps_email_lookup -D /vagrant/dump
```
### Parameters
### -D 
Directory to dump the process in.

Example:
```bash
	-D /vagrant/dump
```
### -p
Process number to search in. Recommended if there are many processes running, or it will crash with out of memory!

Example:
```bash
	-p [102,233,2304]
```




## Timeline
### Setup
I started out with downloading a virtual machine, but ended upon multiple bluescreens, thanks to my Windows installation.. After disabling hyper-v I needed to re-install virtualbox which seemed to fix this problem.

[Vagrant](http://vagrantup.com) is used to quickly setup virtual machine environments.
I use a vagrant box configured by blu3wing in order to get the framework running. This is basically a linux environment with the right python version & dependencies installed, in order to run volatility.

Get vagrant running by creating a *Vagrantfile*:
```bash
Vagrant.configure("2") do |config|
  config.vm.box = "blu3wing/dreamcatcher"
  config.vm.box_version = "2"

  config.vm.synced_folder "shared/", "/vagrant", create: true

  $script = "pip install ratelimit"
  config.vm.provision :shell, privileged: true, inline: $script

end
```
In the shared folder */shared*, we can put all our memory images and code, which gets synchronized with our box.

Pop up a bash shell, boot up the VM, and SSH into the box:
```bash
vagrant up
vagrant ssh
```
(To stop the VM after development, use `vagrant suspend`.)

Now that we are SSHd into the box, we can test it by going into the installation directory and running Volatility:
```bash
cd /opt/volatility #<-- Location of Volatility
python vol.py --info
```
### Development

