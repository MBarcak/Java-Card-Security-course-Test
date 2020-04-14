package purse;

import javacard.framework.JCSystem;

public class CyclicFile {
	// ��¼
	private byte[] record;
	//��󳤶�
	public short maxrecord;
	//��¼����
	public short recordsize;
	//��ǰ��¼λ��
	public short currentrecord;
	//������
	private byte[] buffer;
	
	protected CyclicFile(short size,short max)
	{
		recordsize = size;
		maxrecord = max;
		record = new byte[size*max];  // �൱�ڶ�ά����
		currentrecord = 0;
		buffer = JCSystem.makeTransientByteArray(size, JCSystem.CLEAR_ON_DESELECT);
	}
	// ��ȡĳ����¼
	public byte[] ReadRecord(short num)
	{
		for(short i=0;i<recordsize;i++)
		{
			buffer[i]=record[(num-1)*recordsize+i];
		}
		return buffer;
	}
	// ��Ӽ�¼
	public short AppendRecord(byte[] data,short size)	
	{
		if(size>recordsize)  // ���ڼ�¼����
		{
			return (short)1;
		}
		for(short i=0;i<size;i++){
			record[currentrecord*recordsize+i]=data[i];
		}
		for(short i=size;i<recordsize;i++){
			record[currentrecord*recordsize+i]=(byte)0x00;  //����һ����¼���Ȳ���
		}
		currentrecord++;
		if(currentrecord==maxrecord)  //����ĩβ����ͷ��ѭ��
		{
			currentrecord=0;
		}
		return (short)0;
	}

}

