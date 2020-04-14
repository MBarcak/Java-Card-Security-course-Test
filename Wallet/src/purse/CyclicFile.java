package purse;

import javacard.framework.JCSystem;

public class CyclicFile {
	// 记录
	private byte[] record;
	//最大长度
	public short maxrecord;
	//记录长度
	public short recordsize;
	//当前记录位置
	public short currentrecord;
	//缓存区
	private byte[] buffer;
	
	protected CyclicFile(short size,short max)
	{
		recordsize = size;
		maxrecord = max;
		record = new byte[size*max];  // 相当于二维数组
		currentrecord = 0;
		buffer = JCSystem.makeTransientByteArray(size, JCSystem.CLEAR_ON_DESELECT);
	}
	// 读取某条记录
	public byte[] ReadRecord(short num)
	{
		for(short i=0;i<recordsize;i++)
		{
			buffer[i]=record[(num-1)*recordsize+i];
		}
		return buffer;
	}
	// 添加记录
	public short AppendRecord(byte[] data,short size)	
	{
		if(size>recordsize)  // 大于记录长度
		{
			return (short)1;
		}
		for(short i=0;i<size;i++){
			record[currentrecord*recordsize+i]=data[i];
		}
		for(short i=size;i<recordsize;i++){
			record[currentrecord*recordsize+i]=(byte)0x00;  //不足一条记录长度补零
		}
		currentrecord++;
		if(currentrecord==maxrecord)  //到达末尾返回头，循环
		{
			currentrecord=0;
		}
		return (short)0;
	}

}

