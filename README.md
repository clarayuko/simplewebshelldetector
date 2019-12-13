# simplewebshelldetector
非常简单的webshell检测代码，主要通过文件名、文件内容、文件hash值以及文件是否加密。超级大菜鸟的咸鱼代码。

	#基于python3
	#python webshell_detector.py -r path -f suffix
	#path为路径，suffix为文件格式，默认"ASP|JSP|PHP"
	#blacklist为收集的webshell名称

#根据网上资料，基于文件检测webshell的话：通过文件特征、文件哈希、文 件动态行为、文件访问时间、访问频率、文件权限等属性来鉴别恶意文件。比较菜，所以写的比较简单。


