# Linux Process E-mail Grabber
## About
Developed by Ruben Kluge for the Memory Forensics course at LSU.
*ps_email_lookup.py* --> *linux_ps_email_lookup.py* 

## Why use this plugin?
This plugin can be used to scan memory for e-mail addresses, and determine e-mail age by matching it to the database of [HaveIBeenPwned](https://haveibeenpwned.com/).
This can be useful, as some malware could send details of keyloggers, etc. to a particular e-mail. Indications of no breaches could possibly determine the usage of an e-mail address.

## Usage
1.  Unpack the ZIP file and put the .py files in a directory.
    
2.  install the python dependency ratelimit via the commandline using pip:  
    `pip install ratelimit`
    
3.  Specify the plugin directory with `--plugin=[PATH]`
    
4.  Install your volatility profiles for your system you want to analyze (download into:  
    `/volatility/plu‌​gins/overlays/linux)`
    
5.  Run it with the optional parameters `-p [process]` and `-D [dump directory]`

Example:
```bash
python vol.py --plugins=/vagrant/plugin  --profile=LinuxXubuntu1404x64 -f /vagrant/NILES.lime ps_email_lookup -D /vagrant/dump
```
Output:
```bash
Volatility Foundation Volatility Framework 2.6
PID 	E-mail 						Date 			Breaches
4256 	bash-maintainers@gnu.org 	2017-08-28 		2
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




# Timeline
## Setup
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
## Development
The objective is to search the memory dump (or a process) for e-mail addresses, and send the results to an API. We separate this into two tasks: memory search & API Calling.

### Memory search
How do we analyze the memory to get the e-mail addresses?  A widely used plugin to find malware samples is the YARA scan. YARA scans the memory in 1MB chunks for predefined patterns. In our case, we can't really use YARA scan, as the character match would only be the symbol  `@`. 
However, we can still use Regular Expressions to search for e-mail addresses. The downside of this is that we need to dump the whole process, and run an exhaustive RegEx search on this.  We can further divide this problem in subtasks:

1. Process dumping (either to memory or to a file)
2. Searching a dump for E-mails


#### Process dumping
Let's dive deeper into the process dumping itself. We look at *volatility/plugins/procdump.py* in order to figure out how to dump the process and keep it in memory instead dumping to a file. 
Below we see how *procdump* handles writing memory to a file:
```python
file_path = linux_common.write_elf_file(self._config.DUMP_DIR, task, task.mm.start_code)
```
When we continue to investigate how the *write_elf_file* function works, we stumble upon this (in *volatility/common.py*):
```python
def write_elf_file(dump_dir, task, elf_addr):
	file_name = re.sub("[./\\\]", "", str(task.comm))
	
	file_path = os.path.join(dump_dir, "%s.%d.%#8x" % (file_name, task.pid, elf_addr))
	
	file_contents = task.get_elf(elf_addr)
	
	fd = open(file_path, "wb")
	fd.write(file_contents)
	fd.close()
	
	return file_path
```
This gives us the information that the *task* struct contains the *get_elf* function, which would represent the contents of the file. We can directly use this function to grab a dump of the process!

### API Calling
