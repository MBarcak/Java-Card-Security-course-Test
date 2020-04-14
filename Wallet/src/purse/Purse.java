package purse;

import javacard.framework.AID;
import javacard.framework.APDU;
import javacard.framework.Applet;
import javacard.framework.ISO7816;
import javacard.framework.ISOException;
import javacard.framework.JCSystem;
import javacard.framework.OwnerPIN;
import javacard.framework.Util;
import sampleLoyalty.JavaLoyaltyInterface;
import javacard.security.*;
import javacardx.crypto.*;

public class Purse extends Applet {
	// CLA
	final static byte Wallet_CLA = (byte) 0x80;
	final static byte VERIFY = (byte) 0x20; // ��֤
	final static byte CREDIT = (byte) 0x30; // ���
	final static byte DEBIT = (byte) 0x40; // ȡ��
	final static byte GET_BALANCE = (byte) 0x50; // ��ȡ���
	final static byte READ_FILE = (byte) 0xB2; // ��ȡ��¼�ļ�
	final static byte IN_AUT = (byte) 0x88; // �ڲ���֤
	final static byte OUT_RANDOM = (byte) 0x84; // �ⲿ��֤�����
	final static byte OUT_AUT = (byte) 0x82; // �ⲿ��֤

	// ����DES��Կ
	private byte[] keyData = { 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08 };

	// ������
	final static short MAX_BALANCE = 0x7FFF;
	// ���׶����ֵ
	final static byte MAX_TRANSACTION_AMOUNT = 127;

	// PIN��ೢ�Դ���
	final static byte PIN_TRY_LIMIT = (byte) 0x03;
	// PIN��󳤶�
	final static byte MAX_PIN_SIZE = (byte) 0x08;
	// signal that the PIN verification failed
	final static short SW_VERIFICATION_FAILED = 0x6300;
	// signal the the PIN validation is required
	// for a credit or a debit transaction
	final static short SW_PIN_VERIFICATION_REQUIRED = 0x6301;
	// signal invalid transaction amount
	// amount > MAX_TRANSACTION_AMOUNT or amount < 0
	final static short SW_INVALID_TRANSACTION_AMOUNT = 0x6A83;
	// signal that the balance exceed the maximum
	final static short SW_EXCEED_MAXIMUM_BALANCE = 0x6A84;
	// signal the the balance becomes negative
	final static short SW_NEGATIVE_BALANCE = 0x6A85;
	// ����Applet��AID��223344556601
	byte[] loyaltyAIDValue = { (byte) 0x22, (byte) 0x33, (byte) 0x44,
			(byte) 0x55, (byte) 0x66, (byte) 0x01 };

	byte[] AppletID = { (byte) 0x11, (byte) 0x22, (byte) 0x33,
			(byte) 0x44, (byte) 0x55, (byte) 0x01 };
	
	byte[] sigbuf;  //ǩ������
	
	byte[] tmp; //��֤������ʱ����
	OwnerPIN pin;
	short balance;
	CyclicFile record; // ��¼�ļ�
	private DESKey indeskey; // �ڲ���֤��Կ
	Cipher inCipherObj; // �ڲ���֤���ܶ���
	byte[] Random; // �ⲿ��֤�����
	private DESKey outdeskey; // �ⲿ��֤��Կ
	Cipher outCipherObj; // �ⲿ��֤���ܶ���
	private DESKey mackey;  //mac��Կ
	Signature sig;   //macǩ������


	private Purse(byte[] bArray, short bOffset, byte bLength) {

		byte pinInitValue[] = { 0x01, 0x02, 0x03, 0x04, 0x05, 0x06 };
		pin = new OwnerPIN(PIN_TRY_LIMIT, MAX_PIN_SIZE);
		pin.update(pinInitValue, (short) 0, (byte) 6);
		record = new CyclicFile((short) 14, (short) 5);
		// �����ڲ���֤��Կ����
		indeskey = (DESKey) KeyBuilder.buildKey(KeyBuilder.TYPE_DES,KeyBuilder.LENGTH_DES, false);
		// �����ڲ���֤���ܶ���
		inCipherObj = Cipher.getInstance(Cipher.ALG_DES_CBC_ISO9797_M2, false);
		//����mac��Կ����
		mackey = (DESKey)KeyBuilder.buildKey(KeyBuilder.TYPE_DES, KeyBuilder.LENGTH_DES, false);					
		//����mac��Կ					
		mackey.setKey(keyData, (short)0);
		//��ʼ��ǩ������
		sig = Signature.getInstance(Signature.ALG_DES_MAC8_ISO9797_M2, false);
		tmp = JCSystem.makeTransientByteArray((short)30,JCSystem.CLEAR_ON_DESELECT);
		sigbuf = JCSystem.makeTransientByteArray((short)8,JCSystem.CLEAR_ON_DESELECT);

		register();
	}

	public static void install(byte[] bArray, short bOffset, byte bLength) {

		new Purse(bArray, bOffset, bLength);
	}

	public boolean select() {

		// �ж��Ƿ���֤
		if (pin.getTriesRemaining() == 0)
			return false;
		else
			return true;

	}

	public void deselect() {

		pin.reset();

	}

	public void process(APDU apdu) {

		byte[] buffer = apdu.getBuffer();

		buffer[ISO7816.OFFSET_CLA] = (byte) (buffer[ISO7816.OFFSET_CLA] & (byte) 0xFC);

		if ((buffer[ISO7816.OFFSET_CLA] == 0)
				&& (buffer[ISO7816.OFFSET_INS] == (byte) (0xA4)))
			return;

		if (buffer[ISO7816.OFFSET_CLA] != Wallet_CLA)
			ISOException.throwIt(ISO7816.SW_CLA_NOT_SUPPORTED);

		switch (buffer[ISO7816.OFFSET_INS]) {
		case GET_BALANCE:
			getBalance(apdu);
			return;
		case DEBIT:
			debit(apdu);
			return;
		case CREDIT:
			credit(apdu);
			return;
		case VERIFY:
			verify(apdu);
			return;
		case READ_FILE:
			ReadFile(apdu);
			return;
		case IN_AUT:
			indoAuthentication(apdu);
			return;
		case OUT_RANDOM:
			getRandom(apdu);
			return;
		case OUT_AUT:
			outdoAuthentication(apdu);
			return;
		default:
			ISOException.throwIt(ISO7816.SW_INS_NOT_SUPPORTED);
		}

	}

	private void credit(APDU apdu) {
		// �ж�����
		if (!pin.isValidated())
			ISOException.throwIt(SW_PIN_VERIFICATION_REQUIRED);
		// ��������
		JCSystem.beginTransaction();
		byte[] buffer = apdu.getBuffer();
		byte numBytes = buffer[ISO7816.OFFSET_LC];
		byte byteRead = (byte) (apdu.setIncomingAndReceive());

		// ��ȡ���׶�
		byte creditAmount = buffer[ISO7816.OFFSET_CDATA];
		// ����У������
		tmp[0] = creditAmount;
		tmp[1] = (byte)0xFE; //����ʶ��0xFE
		Util.arrayCopy(AppletID,(short)0,tmp, (short)2, (short)6); // ����AID
		// ǩ��
		Signature(tmp);
		// ��ǩ
		if (!VerifySignature(buffer))
		{
			JCSystem.abortTransaction();
			ISOException.throwIt(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);
		}
		// �жϽ��׶�
		if ((creditAmount > MAX_TRANSACTION_AMOUNT) || (creditAmount < 0)) {
			// ��ֹ����
			JCSystem.abortTransaction();
			ISOException.throwIt(SW_INVALID_TRANSACTION_AMOUNT);
		}
		// ����µ����
		if ((short) (balance + creditAmount) > MAX_BALANCE) {
			// ��ֹ����
			JCSystem.abortTransaction();
			ISOException.throwIt(SW_EXCEED_MAXIMUM_BALANCE);
		}
		// ����
		balance = (short) (balance + creditAmount);
		// ���Ӽ�¼
		record.AppendRecord(buffer, record.recordsize);
		// ���»���
		grantPoints(creditAmount);
		// �ύ����
		JCSystem.commitTransaction();

	} // end of deposit method

	private void debit(APDU apdu) {
		// ͬ��
		if (!pin.isValidated())
			ISOException.throwIt(SW_PIN_VERIFICATION_REQUIRED);
		// ��������
		JCSystem.beginTransaction();

		byte[] buffer = apdu.getBuffer();
		byte numBytes = (byte) (buffer[ISO7816.OFFSET_LC]);
		byte byteRead = (byte) (apdu.setIncomingAndReceive());

		byte debitAmount = buffer[ISO7816.OFFSET_CDATA];
		// ����У������
		tmp[0] = debitAmount;
		tmp[1] = (byte)0xFF; //ȡ���ʶ��0xFF
		Util.arrayCopy(AppletID,(short)0,tmp, (short)2, (short)6); // ����AID
		// ǩ��
		Signature(tmp);
		// ��ǩ
		if (!VerifySignature(buffer))
		{
			JCSystem.abortTransaction();
			ISOException.throwIt(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);
		}
		if ((debitAmount > MAX_TRANSACTION_AMOUNT) || (debitAmount < 0)) {
			// ��ֹ����
			JCSystem.abortTransaction();
			ISOException.throwIt(SW_INVALID_TRANSACTION_AMOUNT);
		}

		if ((short) (balance - debitAmount) < (short) 0) {
			// ��ֹ����
			JCSystem.abortTransaction();
			ISOException.throwIt(SW_NEGATIVE_BALANCE);
		}

		balance = (short) (balance - debitAmount);
		// ���Ӽ�¼
		record.AppendRecord(buffer, record.recordsize);
		// �ύ����
		JCSystem.commitTransaction();
	} // end of debit method

	private void getBalance(APDU apdu) {

		byte[] buffer = apdu.getBuffer();
		// ������Ӧ���ݳ���
		short le = apdu.setOutgoing();
		if (le < 2)
			ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);

		apdu.setOutgoingLength((byte) 2);
		// ����Ӧ����д��buffer
		buffer[0] = (byte) (balance >> 8);
		buffer[1] = (byte) (balance & 0xFF);
		// ����ƫ�Ƶ�ַ0��λ�õ�2byte�����ݷ���
		apdu.sendBytes((short) 0, (short) 2);

	} // end of getBalance method
	
	//PIN��֤
	private void verify(APDU apdu) {

		byte[] buffer = apdu.getBuffer();

		byte byteRead = (byte) (apdu.setIncomingAndReceive());

		if (pin.check(buffer, ISO7816.OFFSET_CDATA, byteRead) == false)
			ISOException.throwIt(SW_VERIFICATION_FAILED);

	} // end of validate method

	private void grantPoints(short points) {

		// �����ӿ�ʵ��
		JavaLoyaltyInterface loyaltySIO;
		// AID
		AID loyaltyAID;

		// ��ȡ�����ӿ����AID
		loyaltyAID = JCSystem.lookupAID(loyaltyAIDValue, (short) (0),
				(byte) (loyaltyAIDValue.length));
		// ��ȡ�����ӿ�ʵ������
		if (loyaltyAID != null)
			loyaltySIO = (JavaLoyaltyInterface) JCSystem
					.getAppletShareableInterfaceObject(loyaltyAID, (byte) 0);
		else
			return;

		// ����
		loyaltySIO.grantPoints(points);
	}// end of grant points method

	// ��ȡ��¼�ļ�
	private void ReadFile(APDU apdu) {

		// ��֤����
		if (!pin.isValidated())
			ISOException.throwIt(SW_PIN_VERIFICATION_REQUIRED);

		byte[] buffer = apdu.getBuffer();
		byte[] data;
		short num = 0;
		// �жϲ���
		if (buffer[ISO7816.OFFSET_P2] == 0x04) {
			num = Util.makeShort((byte) 0x00, buffer[ISO7816.OFFSET_P1]); // ��P1��0x00���ӣ�num=00P1
		} else if (buffer[ISO7816.OFFSET_P2] == 0x00) {

		} else {
			ISOException.throwIt(ISO7816.SW_INCORRECT_P1P2);
		}
		// �ж��Ƿ񳬳��˼�¼��Χ
		if (num > record.maxrecord) {
			ISOException.throwIt(ISO7816.SW_INCORRECT_P1P2);
		}
		// �жϼ�¼�ļ��Ƿ�������
		if (record.currentrecord == -1) {
			ISOException.throwIt(ISO7816.SW_DATA_INVALID);
		}
		num = (short) (record.currentrecord - num);
		if (num <= 0) {
			num = (short) (record.maxrecord + num);
		}
		data = record.ReadRecord(num);
		// �����������
		apdu.setOutgoing();
		apdu.setOutgoingLength(record.recordsize);
		apdu.sendBytesLong(data, (short) 0, record.recordsize);
	}

	// �ڲ���֤����
	private void indoAuthentication(APDU apdu) {

		byte[] buffer = apdu.getBuffer();
		apdu.setIncomingAndReceive();
		// ����DES��Կ
		indeskey.setKey(keyData, (short) 0);
		// ��ʼ����Կ������ģʽ
		inCipherObj.init(indeskey, Cipher.MODE_ENCRYPT);
		// ����
		inCipherObj.doFinal(buffer, (short) 5, (short)8 , buffer, (short) 0);
		// �������ɵ�8�ֽڼ�������
		apdu.setOutgoingAndSend((short) 0, (short) 8);

	}

	// �ⲿ��֤���������
	private void getRandom(APDU apdu) {

		byte[] buffer = apdu.getBuffer();
		apdu.setIncomingAndReceive();
		// ������������������
		if (Random == null)
			Random = JCSystem.makeTransientByteArray((short) 16,
					JCSystem.CLEAR_ON_DESELECT);

		// �������������Ķ���ʵ��
		RandomData ICC = RandomData.getInstance((byte) RandomData.ALG_PSEUDO_RANDOM);
		// ��������������Ӳ�����8�ֽڵ������
		ICC.setSeed(Random, (short) 0, (short) 8);
		ICC.generateData(Random, (short) 0, (short) 8);
		// �������ɵ�8�ֽ������
		Util.arrayCopyNonAtomic(Random, (short) 0, buffer, (short) 0, (short) 8);
		apdu.setOutgoingAndSend((short) 0, (short) 8);

	}

	// �ⲿ��֤
	private void outdoAuthentication(APDU apdu) {

		byte[] buffer = apdu.getBuffer();
		apdu.setIncomingAndReceive();
		// ������Կ����
		outdeskey = (DESKey) KeyBuilder.buildKey(KeyBuilder.TYPE_DES,
				KeyBuilder.LENGTH_DES, false);
		// ����DES��Կ
		outdeskey.setKey(keyData, (short) 0);
		// ���ɼ��ܶ���
		outCipherObj = Cipher.getInstance(Cipher.ALG_DES_CBC_ISO9797_M2, false);
		// ��ʼ����Կ������ģʽ
		outCipherObj.init(outdeskey, Cipher.MODE_ENCRYPT);
		// ����
		outCipherObj.doFinal(Random, (short) 0, (short) 8, buffer, (short) 13);
		// �Ƚ�����������ܽ��
		if (Util.arrayCompare(buffer, (short) 5, buffer, (short) 13, (short) 8) != 0)
			ISOException.throwIt(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);
	}

	private short Signature(byte [] buffer) {

		//��ʼ��ǩ��ģʽ
		sig.init(mackey, Signature.MODE_SIGN);
					  
		//���������ݽ���ǩ���������buffer��
		return sig.sign(buffer, (short)0, (short)8, sigbuf, (short)0);			

	}
	//��ǩ
	private boolean VerifySignature(byte [] buffer) {

		//��ʼ��ǩ��ģʽ
		sig.init(mackey, Signature.MODE_VERIFY);
					  
		//�Դ����buffer�е��������ݽ���ǩ����֤
		if(Util.arrayCompare(buffer, (short)6, sigbuf, (short)0, (short)8)!=0)
			return false;
		else
			return true;

	}

}
