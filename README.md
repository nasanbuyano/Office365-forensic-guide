Office 365 CIS Benchmark - н тохиргоо хийгдсэн эсэхийг SecurescoringOffice365Benchmark.ps1 скриптыг ашиглаж автоматаар шалгана уу. Мөн forensic-guide хавтаснаас Office365 үйлчилгээнд нийтлэг тохиолддог халдлагад өртсөний дараа хэрхэн дүн шинжилгээ хийх зөвлөмжтэй танилцана уу. 

# Скрипт ажиллуулахад шаардлагатай зүйлс

  - https://www.microsoft.com/en-us/download/confirmation.aspx?id=39366 сайтаас skype module татаж суулгах.
  - Install-Module -Name Microsoft.Online.SharePoint.PowerShell 
  - Install-Module MSOnline
  - Azure дээр шинэ аппликэйшн үүсгээд SecurityEvents.ReadWrite.All permission өгөх мөн application id, client secret хоёрыг хадгалж авах ( Дэлгэрэнгүй : https://docs.microsoft.com/en-us/graph/security-authorization 
  
# Жишээ :  

  1. Домайн админ эрхээр ажиллуулах
  ![aaa](/images/domain_credential.png)
  2. Application id болон client secret дээр Azure дээр үүсгэсэн шинэ аппликэйшны id болон secret - г оруулж өгнө. 
  ![aaaa](/images/credentials.png)
  3. success.json, failed.json, score.txt гэсэн файл үүсэх бөгөөд амжилттай хийгдсэн тохиргоо нь жишээ нь дараах байдлаар харагдана. 
  ![bbbb](/images/success.png)
