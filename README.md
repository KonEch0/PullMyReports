# PullMyReports
![image](https://user-images.githubusercontent.com/102297040/159912679-ea121d83-4d48-498f-aa06-40955dddd9ea.png)

PullMyReports is a tool that allows you to automatically download reports from your Nessus Scanner using the Nessus API. This tool, has only been tested on local instances of Nessus, hence the script will assume 8834 to be the port in use.

The intention of this tool, is to automate the tedious task of downloading and renaming all the reports by hand.

# Usage
### Python
```bash
pip install -r requirements.txt
python3 pullmyreports.py

```
### Executable
The compiled version will take abit longer to start, smartscreen might prevent immediate execution.
```
pullmyreports.exe
```
You would need to follow the on screen prompts and fill in the necessary infomation, NOTE: you will need to enter in your Nessus credentials.

# Screenshots
![image](https://user-images.githubusercontent.com/102297040/159913145-8916756a-0795-46e8-8c29-34539253c45c.png)

![image](https://user-images.githubusercontent.com/102297040/159912974-68936d18-a63b-4c57-b2ce-c5c683686a1f.png)

# Disclaimer
The tools and code within this repository have no guarantee, usage comes at own risk.
I do not take responsibility for how anyone chooses to use these tools, with usage, you understand that it is at your own risk.
All tools and code here is designed for educational/research and operational purposes.
