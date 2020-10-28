# Office365-forensic-guide


# Скрипт ажиллуулахад шаардлагатай зүйлс :

  - https://www.microsoft.com/en-us/download/confirmation.aspx?id=39366 сайтаас skype module татаж суулгах.
  - Install-Module -Name Microsoft.Online.SharePoint.PowerShell 
  - Install-Module MSOnline
  - Azure дээр шинэ аппликэйшн үүсгээд SecurityEvents.ReadWrite.All permission өгөх мөн application id, client secret хоёрыг хадгалж авах ( Дэлгэрэнгүй : https://docs.microsoft.com/en-us/graph/security-authorization 
  
# Жишээ :  

  1. Домайн админ эрхээр ажиллуулах
  ![aaa](/images/domain_credential.png)
  2. Application id болон client secret дээр Azure дээр үүсгэсэн шинэ аппликэйшны id болон secret - г оруулж өгнө. 
  ![aaaa](/images/credentials.png)
  
