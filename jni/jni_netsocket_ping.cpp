
#include <jni.h>

#include <fcntl.h>
#include <pthread.h>
#include <errno.h>
#include <sys/mman.h>
#include <stdlib.h>

#include <sys/socket.h>		// socket
#include <netinet/in.h> 	// socket  AF_INET SOCK_RAW  IPPROTO_ICMP
#include <netdb.h>			// getprotobyname gethostbyname
#include <netinet/ip_icmp.h>// struct icmp  ICMP_ECHO ICMP_ECHOREPLY
#include <netinet/ip.h>		// struct ip
#include <arpa/inet.h>		// inet_ntoa(struct in_addr>>字符串) inet_addr(字符串>>长整型)
							//  struct in_addr 是 struct sockaddr_in的成员 sin_addr 类型
							//  struct sockaddr_in 是 struct sockaddr 在以太网的具体实现

#define LOG_TAG "jni_ping"
#include "vortex.h"
#include "NativeContext.h"
#define JAVA_CLASS_PATH "com/hanlon/netapi/Ping"
// 如果写成 com.hanlon.netapi.Ping等.写法 会导致异常 JNI DETECTED ERROR IN APPLICATION: illegal class name
#define TARGET_ADDRESS "localhost"

//static struct {
//    jfieldID    context; 	// NOT IN USED
//    jmethodID   post_event;
//} g_java_fields;

/*保存已经发送包的状态值*/
typedef struct pingm_pakcet{
	struct timeval tv_begin;	/*发送的时间*/
	struct timeval tv_end;		/*接收到的时间*/
	short seq;					/*序列号*/
	int flag;		/*1，表示已经发送但没有接收到回应包0，表示接收到回应包*/
}pingm_pakcet;
static pingm_pakcet pingpacket[128];

typedef struct jni_netsocket_ping_ctx {
	pthread_t mMainth  ;
	pid_t m_pid;						/*进程PID*/
	int mRawSock;					/*发送和接收线程需要的socket描述符*/
	struct sockaddr_in mTargetDest;		/*目的地址*/
	bool mAlive ;					/*是否接收到退出信号*/
	short mPacketSnd  ;			/*已经发送的数据包有多少*/
	short mPacketRcv  ;			/*已经接收的数据包有多少*/

	struct timeval mBeginTime,mEndTime;

	jni_netsocket_ping_ctx():mMainth(-1),m_pid(-1),mRawSock(-1),
							mAlive(true),mPacketSnd(0),mPacketRcv(0)
	{
		memset((void*)&mTargetDest,0,sizeof(mTargetDest));
	}
} JniCtx ;

/*查找一个合适的包位置
*当seq为-1时，表示查找空包
*其他值表示查找seq对应的包*/
static pingm_pakcet *icmp_findpacket(int seq)
{
	int i=0;
	pingm_pakcet *found = NULL;
	/*查找包的位置*/
	if(seq == -1){							/*查找空包的位置*/
		for(i = 0;i<128;i++){
			if(pingpacket[i].flag == 0){
				found = &pingpacket[i];
				break;
			}
		}
	}else if(seq >= 0){						/*查找对应seq的包*/
		for(i = 0;i<128;i++){
			if(pingpacket[i].seq == seq){
				found = &pingpacket[i];
				break;
			}
		}
	}
	return found;
}

/* CRC16 校验和计算icmp_cksum
参数：
	data:数据
	len:数据长度
返回值：
	计算结果，short类型
*/
static unsigned short icmp_cksum(unsigned char *data,  int len)
{
	int sum=0;					/*计算结果*/
	int odd = len & 0x01;		/*是否为奇数*/
	while( len & 0xfffe)  {		/*将数据按照2字节为单位累加起来*/
		sum += *(unsigned short*)data;
		data += 2;
		len -=2;
	}
	if( odd) {					/*判断是否为奇数个数据，若ICMP报头为奇数个字节，会剩下最后一字节*/
		unsigned short tmp = ((*data)<<8)&0xff00;
		sum += tmp;
	}
	sum = (sum >>16) + (sum & 0xffff);	/*高低位相加*/
	sum += (sum >>16) ;					/*将溢出位加入*/
	return ~sum;						/*返回取反值*/
}

/*设置ICMP报文*/
static void icmp_pack(struct icmp *icmph, int seq, int pid ,  struct timeval *tv, int length )
{
	unsigned char i = 0;

	// ICMP公共头
	icmph->icmp_type = ICMP_ECHO;	/*ICMP回显请求*/
	icmph->icmp_code = 0;			/*code值为0*/
	icmph->icmp_cksum = 0;	  		/*先将cksum值填写0，便于之后的cksum计算*/

	// ICMP ECHO头
	icmph->icmp_seq = seq;			/*本报的序列号*/
	icmph->icmp_id = pid &0xffff;	/*填写PID*/

	// ICMP ECHO数据
	for(i = 0; i< length; i++)
		icmph->icmp_data[i] = i;	//????

	icmph->icmp_cksum = icmp_cksum((unsigned char*)icmph, length);/*计算校验和*/
}

/*计算时间差time_sub
参数：
	end，接收到的时间
	begin，开始发送的时间
返回值：
	使用的时间
*/
static inline int icmp_tvsub(struct timeval end,struct timeval begin)
{
	return (end.tv_sec - begin.tv_sec)*1000 + (end.tv_usec - begin.tv_usec)/1000 ;
}


/*解压接收到的包，并打印信息*/
static int icmp_unpack(unsigned char *buf, int len , pid_t pid )
{
	int iphdrlen;
	struct ip *ip = NULL;
	struct icmp *icmp = NULL;
	int rtt;

	ip=(struct ip *)buf; 					/*IP头部*/
	iphdrlen= ip->ip_hl * 4;				/*IP头部长度*/
	icmp=(struct icmp *)( buf + iphdrlen);	/*ICMP段的地址*/
	len -= iphdrlen;
	if( len < 8 ){							/*判断长度是否为ICMP包*/
		ALOGE("ICMP packets\'s length is less than 8 , dump data:\n");
		for(int i = 0 ; i < len ; i++ ){
			ALOGE("data [%d] 0x%0x " , i , buf[iphdrlen + i]);
		}
		return -1;
	}
	/*ICMP类型为ICMP_ECHOREPLY并且为本进程的PID*/
	if( (icmp->icmp_type==ICMP_ECHOREPLY) && (icmp->icmp_id== pid) )
	{
		struct timeval tv_recv,tv_send;
		pingm_pakcet* packet = icmp_findpacket(icmp->icmp_seq);
		if(packet == NULL){					/*在发送表格中查找已经发送的包，按照seq*/
			ALOGE("ICMP get reply twice ?? seq %d " ,icmp->icmp_seq);
			return -1;
		}
		packet->flag = 0;					/*取消标志*/
		tv_send = packet->tv_begin;			/*获取本包的发送时间*/
		gettimeofday(&tv_recv, NULL);		/*读取此时间，计算时间差*/
		rtt =  icmp_tvsub(tv_recv,tv_send);
		/*打印结果，包含
		*  ICMP段长度
		*  源IP地址 (从IP包的头)
		*  包的序列号
		*  TTL
		*  时间差
		*/
		printf("%d byte from %s: icmp_seq=%u ttl=%d rtt=%d ms\n",
			len,
			inet_ntoa(ip->ip_src),			// ip包来自哪里  struct ip.ip_src ip.ip_dst
			icmp->icmp_seq,
			ip->ip_ttl,
			rtt);

	}else{
		ALOGE("icmp_type = %d icmp_id = %d , icmp is not what sent" , icmp->icmp_type , icmp->icmp_id );
		return -1;
	}
	return 0;
}

/*发送ICMP回显请求包*/
static void* icmp_send(void *argv)
{
	JniCtx* pCtx = (JniCtx*) ((NativeContext*)argv)->mJNIcontext ;
	unsigned int len_send_buff = 72; //
	unsigned char* send_buff = (unsigned char* )malloc(len_send_buff) ;

	while(pCtx->mAlive)
	{
		int size = 0;
		struct timeval tv;
		gettimeofday(&tv, NULL);			/*当前包的发送时间*/
		/*在发送包状态数组中找一个空闲位置*/
		pingm_pakcet *packet = icmp_findpacket(-1);
		if(packet)
		{
			packet->seq = pCtx->mPacketSnd;		/*设置seq*/
			packet->flag = 1;				/*已经使用*/
			gettimeofday( &packet->tv_begin, NULL);	/*发送时间*/
		}else{
			ALOGE("send packets is empty , receive any ICMP ECHO REPLY yet ?? ");
			sleep(2);
			continue ;
		}

		icmp_pack((struct icmp *)send_buff, pCtx->m_pid , pCtx->mPacketSnd, &tv, 64 );
		/*打包数据*/
		size = sendto ( pCtx->mRawSock,  send_buff, 64,  0,		/*发送给目的地址*/
						(struct sockaddr *)&pCtx->mTargetDest, sizeof(pCtx->mTargetDest) );
		if(size <0)
		{
			perror("sendto error");
			continue;
		}
		 pCtx->mPacketSnd ++;					/*计数增加*/
		/*每隔1s，发送一个ICMP回显请求包*/
		sleep(1);
	}
}

/*接收ping目的主机的回复*/
static void *icmp_recv(void *argv)
{
	JniCtx* pCtx = (JniCtx*) ((NativeContext*)argv)->mJNIcontext ;
	/*轮询等待时间*/
	struct timeval tv;
	tv.tv_usec = 200;
	tv.tv_sec = 0;
	fd_set  readfd;
	struct sockaddr_in from;
	unsigned int len_from = sizeof(from);

	unsigned int len_recv_buffer = 2*1024;
	unsigned char* recv_buff = (unsigned char*)malloc(len_recv_buffer) ; /*为防止接收溢出，接收缓冲区设置大一些*/

	/*当没有信号发出一直接收数据*/
	while(pCtx->mAlive)
	{
		int ret = 0;
		FD_ZERO(&readfd);
		FD_SET( pCtx->mRawSock, &readfd);
		ret = select( pCtx->mRawSock + 1, &readfd, NULL, NULL, &tv);
		switch(ret){
			case -1: /*错误发生*/
				break;
			case 0:  /*超时*/
				break;
			default:{
				/*接收数据*/
				long int size = recvfrom( pCtx->mRawSock, recv_buff, len_recv_buffer,
											MSG_TRUNC, // 如果报文大于缓冲区 依旧返回报文实际大小
											(sockaddr *)&from,
											&len_from);
				if(errno == EINTR) {
					ALOGE("recvfrom error %d  %s " , errno , strerror(errno));
					continue;
				}else if(size > len_recv_buffer){		/*缓冲区太小了*/
					ALOGE("recefrom buffer too small");
					continue;
				}else{
					ret = icmp_unpack(recv_buff, size ,pCtx->m_pid); /*解包，并设置相关变量*/
					if(ret == 0){
						pCtx->mPacketRcv++;				/*成功接收包数量加1*/
					}else{
						ALOGE("icmp_unpack error ... ret = %d " , ret );
						continue;
					}
				}
				break;
			}

		}
	}
	free(recv_buff);

	return NULL;
}

/*打印全部ICMP发送接收统计结果*/
static void icmp_statistics(JniCtx* pCtx )
{
	long time = (pCtx->mEndTime.tv_sec - pCtx->mBeginTime.tv_sec) * 1000
				+ (pCtx->mEndTime.tv_usec - pCtx->mBeginTime.tv_usec) / 1000 ;
	printf("--- %s ping statistics ---\n",TARGET_ADDRESS);					/*目的IP地址*/
	printf("%d packets transmitted, %d received, %d%% packet loss, time %ldms\n",
			pCtx->mPacketSnd,												/*发送*/
			pCtx->mPacketRcv,  												/*接收*/
			(pCtx->mPacketSnd-pCtx->mPacketRcv)*100/pCtx->mPacketSnd, 			/*丢失百分比*/
			time); 															/*时间*/
}


static void* main_thread (void* ctx){

	JniCtx* pCtx = (JniCtx*) ((NativeContext*)ctx)->mJNIcontext ;

	/*为了与其他进程的ping程序区别，加入pid*/
	pCtx->m_pid = getuid();

	struct protoent *protocol = NULL;
	/*获取协议类型ICMP*/
	protocol = getprotobyname("icmp");
	if (protocol == NULL){
		ALOGE("getprotobyname fail force !");
		//return NULL;
		// IPPROTO_ICMP = 1
	}else{
		ALOGI("getprotobyname %s %d", protocol->p_name,protocol->p_proto);
	}

	/*输入的目的地址为字符串IP地址*/
	unsigned long inaddr = inet_addr(TARGET_ADDRESS);
	if(inaddr == INADDR_NONE)	/*输入的是域名/DNS地址 需要先查询DNS */
	{
		struct hostent * host = NULL;
		host = gethostbyname(TARGET_ADDRESS);
		if(host == NULL){
			perror("gethostbyname");
			return NULL;
		}
		/*host->h_addr_list数组 保存所有这个域名的ip地址
		 * 		h_addr         指向第一个ip地址
		 *  将第一个地址复制到dest中*/
		memcpy((char *)&pCtx->mTargetDest.sin_addr, host->h_addr, host->h_length);
	} else {					/*为IP地址字符串*/
		memcpy((char *)&pCtx->mTargetDest.sin_addr, &inaddr, sizeof(inaddr));
	}

	/*打印提示*/
	inaddr = pCtx->mTargetDest.sin_addr.s_addr ;
	ALOGI("PING %s (%ld.%ld.%ld.%ld) 56(84) bytes of data.\n",
			TARGET_ADDRESS ,
			(inaddr&0x000000FF)>>0, // 大端 最低字节是最高位 192 in 192.168.1.100
			(inaddr&0x0000FF00)>>8,
			(inaddr&0x00FF0000)>>16,
			(inaddr&0xFF000000)>>24);


	/*socket初始化*/
	pCtx->mRawSock = socket( AF_INET, SOCK_RAW, IPPROTO_ICMP);
	if(pCtx->mRawSock < 0 ){
		ALOGE("create raw socket error ! %d %s " , errno , strerror(errno));
		return NULL;
	}

	/*增大接收缓冲区，防止接收的包被覆盖*/
	int size = 128 * 1024;
	if ( setsockopt( pCtx->mRawSock,
			SOL_SOCKET, SO_RCVBUF,
			(void*)&size, sizeof(size) )< 0){
		ALOGE("setsockopt SO_RCVBUF error %d %s " , errno , strerror(errno));
	}

	/*接收到的数据包含IP头部*/
//	int set = 1 ;
//	if( setsockopt((int)pNativeContext->m_rawsock,
//			IPPROTO_IP , IP_HDRINCL,
//			(void*)&set , sizeof(set)) < 0 ){
//		ALOGE("setsockopt IP_HDRINCL error %d %s " , errno , strerror(errno));
//	}

	pCtx->mAlive = true ;
	pCtx->mPacketSnd = 0 ;
	pCtx->mPacketRcv = 0 ;
	pthread_t send_id, recv_id;		/*建立两个线程，用于发送和接收*/
	int err = 0;
	err = pthread_create(&send_id, NULL, icmp_send, ctx);		/*发送*/
	if(err < 0){
		return NULL;
	}
	err = pthread_create(&recv_id, NULL, icmp_recv, ctx);		/*接收*/
	if(err < 0){
		return NULL;
	}

	/*等待线程结束*/
	pthread_join(send_id, NULL);
	pthread_join(recv_id, NULL);
	/*清理并打印统计结果*/
	close( pCtx->mRawSock);
	icmp_statistics(pCtx); // mBeginTime,mEndTime;

	return NULL;
}

JNIEXPORT jlong JNICALL native_ping_start (JNIEnv * env , jobject jobj )
{
	JavaVM* jvm ;
	env->GetJavaVM(&jvm);
	NativeContext* ctx = new NativeContext(jvm);
	JniCtx* pCtx = new JniCtx();
	ctx->mJNIcontext = (void*)pCtx;
	// 保存程序开始发送数据的时间
	gettimeofday(&pCtx->mBeginTime, NULL);
	// 启动ping线程处理icmp echo任务
	int ret = ::pthread_create(&pCtx->mMainth , NULL, ::main_thread, ctx );
	if( ret != 0 ){
		ALOGE("create native main thread error !");
	}
	return (jlong)ctx ;
}


JNIEXPORT void JNICALL native_ping_stop (JNIEnv * env , jobject jobj , jlong ctx)
{
	JniCtx* pCtx = (JniCtx*) ((NativeContext*)ctx)->mJNIcontext ;
	gettimeofday(&pCtx->mEndTime, NULL);
	pCtx->mAlive = true;
	pthread_join(pCtx->mMainth, NULL);
	delete pCtx ;
	delete (NativeContext*)ctx;
}

jboolean register_jni_netsocket_ping(JavaVM* vm, JNIEnv* env)
{
	jclass clazz;
	clazz = env->FindClass(JAVA_CLASS_PATH );
	if (clazz == NULL) {
		ALOGE("%s:Class Not Found" , JAVA_CLASS_PATH );
		return JNI_ERR ;
	}

	JNINativeMethod method_table[] = {
		{ "start_ping", "()J", (void*)native_ping_start },
		{ "stop_ping","(J)V", (void*)native_ping_stop },
	};
	jniRegisterNativeMethods( env, JAVA_CLASS_PATH ,  method_table, NELEM(method_table)) ;

//	// 查找Java对应field属性
//	field fields_to_find[] = {
//			{ JAVA_CLASS_PATH , "mNativeContext",  "J", &g_java_fields.context },
//	};
//
//	find_fields( env , fields_to_find, NELEM(fields_to_find) );

	// 查找Java对应method方法
//	g_java_fields.post_event = env->GetMethodID(clazz,
//	    											"postEventFromNative",
//	    			 								"(ILjava/lang/String;)V");
//
//	if (g_java_fields.post_event == NULL) {
//		ALOGE("Can't find android/hardware/Camera.postEventFromNative");
//		return -1;
//	}
	return JNI_TRUE ;
}

