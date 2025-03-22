data<-scan("throughput.txt")
pdf("throughput.pdf")
hist(data, col="dark red", xlab="Throughput (Mb/s)")
grid(col="black", lwd=2);
box();
dev.off();
