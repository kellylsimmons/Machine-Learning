# -*- coding: utf-8 -*-
"""
Created on Fri Jul 17 14:11:15 2015

@author: student
"""

import pandas as pd
import random
import datetime
from pandas.tseries.offsets import *
import numpy as np
import matplotlib.pyplot as plt

data = pd.DataFrame(columns=['IP','User_Agents','Sessions','First_Seen','Last_Seen','Number_Of_Ports'])

'''
def random_date():
    year = []
    for i in range(n):
        y = random.randrange(2010,2016)
        m = random.randrange(1,13)
        if m == 2: #not accounting for leap years
            d = random.randrange(1,29)
        elif m in [1,3,5,7,8,10,12]:
            d = random.randrange(1,32)
        else:
            d = random.randrange(1,31)
        y = datetime.datetime(y,m,d)
        year.append(y)
    date = pd.Series(year)
    return date 
'''

n = 1000
IP = []
User_Agents = []
Sessions = []
Ports = []
i = 0
while i < n:
    x = str(random.randrange(1,255))+'.'+str(random.randrange(1,255))+'.'+str(random.randrange(1,255))+'.'+str(random.randrange(1,255))
    IP.append(x)
    ua = round(np.abs(random.gauss(1,1)),2)
    User_Agents.append(ua)
    s = round(np.abs(random.gauss(20,5)),2)
    Sessions.append(s)
    ports = round(np.abs(random.gauss(5,3)),2)
    Ports.append(ports)
    i += 1

#creating dict to place into dataframe

date = pd.date_range('1/1/2010',periods = n)
First_Seen = []
Last_Seen = []
Age = []

for i in date:
    f = i+datetime.timedelta(random.randrange(1,1800))
    l = f+datetime.timedelta(random.randrange(1,400))
    d = l-f
    First_Seen.append(f)
    Last_Seen.append(l)
    Age.append(d)



raw_data = pd.DataFrame({'IP':IP,
            'User_Agents':User_Agents,
            'Sessions':Sessions,
            'Ports':Ports,
            'First_Seen':First_Seen,
            'Last_Seen':Last_Seen,
            'Age':Age})

#Reordering Columns
raw_data['Age_In_Days']=(raw_data.Age / np.timedelta64(1, 'D')).astype(int)
data = raw_data[['IP','User_Agents','Sessions','Ports', 'First_Seen','Last_Seen','Age_In_Days']]


#############################
#Making Second Cluster-perhaps an intrusion subset looking at just a few ports 
#############################
n2 = 100
IP = []
User_Agents = []
Sessions = []
Ports = []
Days_Seen = []
i = 0
#This cluster should look like attempts to explore the network.  Even though IP changed,  there is still plently of funny activity
while i < n2:
    x = str(random.randrange(1,255))+'.'+str(random.randrange(1,255))+'.'+str(random.randrange(1,255))+'.'+str(random.randrange(1,255))
    IP.append(x)
    #adding a crazy amount of UserAgents, 30+in a month
    ua = round(np.abs(random.gauss(25,3)),2)
    User_Agents.append(ua)
    #Lots of Useragents with lots of hits
    s = round(np.abs(random.gauss(80,20)),2)
    Sessions.append(s)
    #on just a few ports
    ports = round(np.abs(random.gauss(20,1)),2)
    Ports.append(ports)
    i += 1
        
date = pd.date_range('1/1/2010',periods = n2)
First_Seen = []
Last_Seen = []
Age = []

for i in date:
    f = i+datetime.timedelta(random.randrange(1,1800))
    l = f+datetime.timedelta(random.randrange(1,400))
    d = l-f
    First_Seen.append(f)
    Last_Seen.append(l)
    Age.append(d)



bad_data = pd.DataFrame({'IP':IP,
            'User_Agents':User_Agents,
            'Sessions':Sessions,
            'Ports':Ports,
            'First_Seen':First_Seen,
            'Last_Seen':Last_Seen,
            'Age':Age})

#Reordering Columns
bad_data['Age_In_Days']=(raw_data.Age / np.timedelta64(1, 'D')).astype(int)
malicious_data = bad_data[['IP','User_Agents','Sessions','Ports', 'First_Seen','Last_Seen','Age_In_Days']]
    
test = malicious_data.append(data)


####################################33
#Making Third Data Set
#####################


n3 = 50
IP = []
User_Agents = []
Sessions = []
Ports = []
Days_Seen = []
i = 0
#This cluster should look like attempts to explore the network.  Even though IP changed,  there is still plently of funny activity
while i < n3:
    x = str(random.randrange(1,255))+'.'+str(random.randrange(1,255))+'.'+str(random.randrange(1,255))+'.'+str(random.randrange(1,255))
    IP.append(x)
    #adding a medium amount of UserAgents, tightly clustered
    ua = round(np.abs(random.gauss(15,1)),2)
    User_Agents.append(ua)
    #Lots of Sessions, tightly clustered
    s = round(np.abs(random.gauss(60,1)),2)
    Sessions.append(s)
    #on just a few ports
    ports = round(np.abs(random.gauss(2,1)),2)
    Ports.append(ports)
    i += 1
        
date = pd.date_range('1/1/2010',periods = n3)
First_Seen = []
Last_Seen = []
Age = []

for i in date:
    f = i+datetime.timedelta(random.randrange(1,1800))
    l = f+datetime.timedelta(random.randrange(1,400))
    d = l-f
    First_Seen.append(f)
    Last_Seen.append(l)
    Age.append(d)



third_data = pd.DataFrame({'IP':IP,
            'User_Agents':User_Agents,
            'Sessions':Sessions,
            'Ports':Ports,
            'First_Seen':First_Seen,
            'Last_Seen':Last_Seen,
            'Age':Age})

#Reordering Columns
third_data['Age_In_Days']=(raw_data.Age / np.timedelta64(1, 'D')).astype(int)
tight_data = third_data[['IP','User_Agents','Sessions','Ports', 'First_Seen','Last_Seen','Age_In_Days']]
    

final = test.append(tight_data)

'''
plt.scatter(test2.User_Agents,test2.Sessions) 
plt.xlabel('User_Agents')
plt.ylabel('Sessions')
plt.show()
plt.scatter(test2.Ports,test2.Sessions)
plt.xlabel('Ports')
plt.ylabel('Sessions')
plt.show()
plt.scatter(test2.User_Agents,test2.Ports)
plt.xlabel('User_Agents')
plt.ylabel('Ports')
plt.show()
'''

final.to_csv('Simulated_Network_Metrics.csv',index=False)
