WARNING 

MOST LIKELY WONT WORK BECAUSE WE HAD NO ACCESS TO A CP TESTING ROUND





<<<< OVERALL WINDOWS TWEAKS >>>>


1️⃣ COPY the Secure-Windows.ps1 CODE in the top right
<img width="218" height="72" alt="image" src="https://github.com/user-attachments/assets/606c9df8-4b2b-47cf-83e5-7078a95c9b6f" />

2️⃣ Open PowerShell as Administrator 🔍 Search “PowerShell” → Right-click → “Run as Administrator” 

3️⃣ Paste code in and click enter 

4️⃣ if its blocked use Set-ExecutionPolicy -Scope CurrentUser RemoteSigned -Force



<<<< USERS >>>>


(cool tip: use "wmic useraccount get name" in cmd to test)
(helps to use File name extensions in the view part of file manager)

Download all the code and make sure that all the extensions are correct

Make a folder named anything you want

Put the Bat file the ps1 file and the Condition file in 

Go into the bat file and right under "set working folder" you will see a directory replace the directory with the folder directory so cd "C:\user\ExampleUser\Desktop\folder"   will be    cd "C:\user\you\Desktop\folder name"

Change the Condition contents to the users in the format (Users, Acsess level) ex, (james, user)

Lastly run the bat file as a administrator



