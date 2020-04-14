package sampleLoyalty;

import javacard.framework.AID;
import javacard.framework.APDU;
import javacard.framework.Applet;
import javacard.framework.ISO7816;
import javacard.framework.ISOException;
import javacard.framework.Shareable;
import javacard.framework.Util;

public class JavaLoyalty extends Applet implements JavaLoyaltyInterface {

	final static byte LOYALTY_CLA = (byte) 0x90; // CLA
	final static byte READ_BALANCE = (byte) 0x20; // 读取积分
	final static byte RESET_BALANCE = (byte) 0x22; // 清空积分
	final static byte CREDIT = (byte) 0x01; // 存款
	final static byte DEBIT = (byte) 0x02; // 取款
	final static short TRANSACTION_AMOUNT_OFFSET = 0;
	final static short SCALE = (short) 1; // 比例，$1=1积分
	final static short BALANCE_MAX = (short) 30000; 
	
	short balance;

	/**
	 * Installs Java Loyalty applet.
	 * 
	 * @param bArray
	 *            install parameter array.
	 * @param bOffset
	 *            where install data begins.
	 * @param bLength
	 *            install parameter data length.
	 */
	public static void install(byte[] bArray, short bOffset, byte bLength) {
		new JavaLoyalty(bArray, bOffset, bLength);
	}

	/**
	 * Performs memory allocations, initializations, and applet registration
	 * 
	 * @param bArray
	 *            received by install.
	 * @param bOffset
	 *            received by install.
	 * @param bLength
	 *            received by install.
	 */
	protected JavaLoyalty(byte[] bArray, short bOffset, byte bLength) {
		balance = (short) 0;
		/*
		 * if AID length is not zero register Java Loyalty applet with specified
		 * AID
		 * 
		 * NOTE: all the memory allocations should be performed before
		 * register()
		 */

		byte aidLen = bArray[bOffset];
		if (aidLen == (byte) 0) {
			register();
		} else {
			register(bArray, (short) (bOffset + 1), aidLen);
		}
	}

	/**
	 * Implements getShareableInterfaceObject method of Applet class.
	 * <p>
	 * JavaLoyalty could check here if the clientAID is that of JavaPurse
	 * Checking of the parameter to be agreed upon value provides additional
	 * security, or, if the Shareable Interface Object weren't JavaLoyalty
	 * itself it could return different Shareable Interface Objects for
	 * different values of clientAID and/or parameter.
	 * <p>
	 * See<em>Java Card Runtime Environment (JCRE) Specification</em> for
	 * details.
	 * 
	 * @param clientAID
	 *            AID of the client
	 * @param parameter
	 *            additional parameter
	 * @return JavaLoyalty object
	 */

	public Shareable getShareableInterfaceObject(AID clientAID, byte parameter) {
		// 返回当前对象的引用
		if (parameter == (byte) 0)
			return this;
		else
			return null;

	}

	/**
	 * Implements main interaction with a client. The data is transfered through
	 * APDU buffer which is a global array accessible from any context. The
	 * format of data in the buffer is subset of Transaction Log record format:
	 * 2 bytes of 0, 1 byte of transaction type, 2 bytes amount of transaction,
	 * 4 bytes of CAD ID, 3 bytes of date, and 2 bytes of time. This sample
	 * implementation ignores everything but transaction type and amount.
	 * 
	 * @param buffer
	 *            APDU buffer
	 */

	public void grantPoints(short points) {

		balance = (short) (balance + points);

		if (balance > BALANCE_MAX)
			balance = BALANCE_MAX;

	}

	/**
	 * Dispatches APDU commands.
	 * 
	 * @param apdu
	 *            APDU
	 */
	public void process(APDU apdu) {
		byte[] buffer = apdu.getBuffer();
		
		buffer[ISO7816.OFFSET_CLA] = (byte) (buffer[ISO7816.OFFSET_CLA] & (byte) 0xFC);

		if (buffer[ISO7816.OFFSET_CLA] == LOYALTY_CLA) {
			switch (buffer[ISO7816.OFFSET_INS]) {
			case READ_BALANCE:
				processReadBalance(apdu);
				break;
			case RESET_BALANCE:
				processResetBalance();
				break;
			default:
				ISOException.throwIt(ISO7816.SW_INS_NOT_SUPPORTED);
			}
		} else if (selectingApplet())
			return;
		else
			ISOException.throwIt(ISO7816.SW_CLA_NOT_SUPPORTED);
	}


	void processReadBalance(APDU apdu) {
		byte[] buffer = apdu.getBuffer();
		Util.setShort(buffer, (short) 0, balance);
		apdu.setOutgoingAndSend((short) 0, (short) 2);
	}

	void processResetBalance() {
		balance = (short) 0;
	}

}
