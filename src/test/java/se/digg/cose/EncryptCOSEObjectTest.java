// SPDX-FileCopyrightText: 2016-2024 COSE-JAVA
// SPDX-FileCopyrightText: 2025 IDsec Solutions AB
//
// SPDX-License-Identifier: BSD-3-Clause

package se.digg.cose;

import static org.junit.Assert.*;

import com.upokecenter.cbor.*;
import java.util.List;
import org.bouncycastle.crypto.InvalidCipherTextException;
import org.junit.*;
import org.junit.rules.ExpectedException;
import se.digg.cose.AlgorithmID;
import se.digg.cose.Attribute;
import se.digg.cose.COSEKey;
import se.digg.cose.COSEObject;
import se.digg.cose.COSEObjectTag;
import se.digg.cose.CoseException;
import se.digg.cose.EncryptCOSEObject;
import se.digg.cose.HeaderKeys;
import se.digg.cose.KeyKeys;
import se.digg.cose.Recipient;

/**
 *
 * @author jimsch
 */
public class EncryptCOSEObjectTest extends TestBase {

  static byte[] rgbKey128 = {
    'a',
    'b',
    'c',
    4,
    5,
    6,
    7,
    8,
    9,
    10,
    11,
    12,
    13,
    14,
    15,
    16,
  };
  static byte[] rgbKey256 = {
    'a',
    'b',
    'c',
    4,
    5,
    6,
    7,
    8,
    9,
    10,
    11,
    12,
    13,
    14,
    15,
    16,
    17,
    18,
    19,
    20,
    21,
    22,
    23,
    24,
    25,
    26,
    27,
    28,
    29,
    30,
    31,
    32,
  };
  static byte[] rgbContent = {
    'T',
    'h',
    'i',
    's',
    ' ',
    'i',
    's',
    ' ',
    's',
    'o',
    'm',
    'e',
    ' ',
    'c',
    'o',
    'n',
    't',
    'e',
    'n',
    't',
  };
  static byte[] rgbIV128 = {
    0,
    1,
    2,
    3,
    4,
    5,
    6,
    7,
    8,
    9,
    10,
    11,
    12,
    13,
    14,
    15,
  };
  static byte[] rgbIV96 = { 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11 };

  Recipient recipient128;
  COSEKey cnKey128;

  @Rule
  public ExpectedException thrown = ExpectedException.none();

  @Before
  public void setUp() throws CoseException {
    recipient128 = new Recipient();
    recipient128.addAttribute(
      HeaderKeys.Algorithm,
      AlgorithmID.Direct.AsCBOR(),
      Attribute.UNPROTECTED
    );
    CBORObject key128 = CBORObject.NewMap();
    key128.Add(KeyKeys.KeyType.AsCBOR(), KeyKeys.KeyType_Octet);
    key128.Add(KeyKeys.Octet_K.AsCBOR(), CBORObject.FromObject(rgbKey128));
    cnKey128 = new COSEKey(key128);
    recipient128.SetKey(cnKey128);
  }

  /**
   * Test of Decrypt method, of class Encrypt0COSEObject.
   */
  @Test
  public void testRoundTrip() throws Exception {
    System.out.println("Round Trip");
    EncryptCOSEObject msg = new EncryptCOSEObject();
    msg.addAttribute(
      HeaderKeys.Algorithm,
      AlgorithmID.AES_GCM_128.AsCBOR(),
      Attribute.PROTECTED
    );
    msg.addAttribute(
      HeaderKeys.IV,
      CBORObject.FromObject(rgbIV96),
      Attribute.PROTECTED
    );
    msg.SetContent(rgbContent);
    msg.addRecipient(recipient128);
    msg.encrypt();

    List<Recipient> rList = msg.getRecipientList();
    assertEquals(rList.size(), 1);

    byte[] rgbMsg = msg.EncodeToBytes();

    msg = (EncryptCOSEObject) COSEObject.DecodeFromBytes(
      rgbMsg,
      COSEObjectTag.Encrypt
    );
    Recipient r = msg.getRecipient(0);
    r.SetKey(cnKey128);
    byte[] contentNew = msg.decrypt(r);

    assertArrayEquals(rgbContent, contentNew);
  }

  @Test
  public void testGetRecipientCount() {
    EncryptCOSEObject msg = new EncryptCOSEObject();

    assertEquals(msg.getRecipientCount(), 0);

    Recipient r = new Recipient();
    msg.addRecipient(r);
    assertEquals(msg.getRecipientCount(), 1);
  }

  @Test
  public void encryptNoRecipients()
    throws CoseException, InvalidCipherTextException, Exception {
    EncryptCOSEObject msg = new EncryptCOSEObject();

    thrown.expect(CoseException.class);
    thrown.expectMessage("No recipients supplied");
    msg.addAttribute(
      HeaderKeys.Algorithm,
      AlgorithmID.AES_GCM_128.AsCBOR(),
      Attribute.PROTECTED
    );
    msg.SetContent(rgbContent);
    msg.encrypt();
  }

  @Test
  public void encryptNoAlgorithm()
    throws CoseException, InvalidCipherTextException, Exception {
    EncryptCOSEObject msg = new EncryptCOSEObject();
    msg.addRecipient(recipient128);

    thrown.expect(CoseException.class);
    thrown.expectMessage("No Algorithm Specified");
    msg.SetContent(rgbContent);
    msg.encrypt();
  }

  @Test
  public void encryptUnknownAlgorithm()
    throws CoseException, InvalidCipherTextException, Exception {
    EncryptCOSEObject msg = new EncryptCOSEObject();
    msg.addRecipient(recipient128);

    thrown.expect(CoseException.class);
    thrown.expectMessage("Unknown Algorithm Specified");
    msg.addAttribute(
      HeaderKeys.Algorithm,
      CBORObject.FromObject("Unknown"),
      Attribute.PROTECTED
    );
    msg.SetContent(rgbContent);
    msg.encrypt();
  }

  @Test
  public void encryptUnsupportedAlgorithm()
    throws CoseException, InvalidCipherTextException, Exception {
    EncryptCOSEObject msg = new EncryptCOSEObject();
    msg.addRecipient(recipient128);

    thrown.expect(CoseException.class);
    thrown.expectMessage("Unsupported Algorithm Specified");
    msg.addAttribute(
      HeaderKeys.Algorithm,
      AlgorithmID.HMAC_SHA_256.AsCBOR(),
      Attribute.PROTECTED
    );
    msg.SetContent(rgbContent);
    msg.encrypt();
  }

  @Test
  public void encryptNoContent()
    throws CoseException, InvalidCipherTextException, Exception {
    EncryptCOSEObject msg = new EncryptCOSEObject();
    msg.addRecipient(recipient128);

    thrown.expect(CoseException.class);
    thrown.expectMessage("No Content Specified");
    msg.addAttribute(
      HeaderKeys.Algorithm,
      AlgorithmID.AES_GCM_128.AsCBOR(),
      Attribute.PROTECTED
    );
    msg.encrypt();
  }

  @Test
  public void encryptBadIV()
    throws CoseException, InvalidCipherTextException, Exception {
    EncryptCOSEObject msg = new EncryptCOSEObject();
    msg.addRecipient(recipient128);

    thrown.expect(CoseException.class);
    thrown.expectMessage("IV is incorrectly formed");
    msg.addAttribute(
      HeaderKeys.Algorithm,
      AlgorithmID.AES_GCM_128.AsCBOR(),
      Attribute.PROTECTED
    );
    msg.addAttribute(
      HeaderKeys.IV,
      CBORObject.FromObject("IV"),
      Attribute.UNPROTECTED
    );
    msg.SetContent(rgbContent);
    msg.encrypt();
  }

  @Test
  public void encryptIncorrectIV()
    throws CoseException, InvalidCipherTextException, Exception {
    EncryptCOSEObject msg = new EncryptCOSEObject();
    msg.addRecipient(recipient128);

    thrown.expect(CoseException.class);
    thrown.expectMessage("IV size is incorrect");
    msg.addAttribute(
      HeaderKeys.Algorithm,
      AlgorithmID.AES_GCM_128.AsCBOR(),
      Attribute.PROTECTED
    );
    msg.addAttribute(HeaderKeys.IV, rgbIV128, Attribute.UNPROTECTED);
    msg.SetContent(rgbContent);
    msg.encrypt();
  }

  @Test
  public void encryptDecodeWrongBasis() throws CoseException {
    CBORObject obj = CBORObject.NewMap();

    thrown.expect(CoseException.class);
    thrown.expectMessage("COSEObject is not a COSE security COSEObject");

    byte[] rgb = obj.EncodeToBytes();
    COSEObject msg = COSEObject.DecodeFromBytes(rgb, COSEObjectTag.Encrypt);
  }

  @Test
  public void encryptDecodeWrongCount() throws CoseException {
    CBORObject obj = CBORObject.NewArray();
    obj.Add(CBORObject.False);

    thrown.expect(CoseException.class);
    thrown.expectMessage("Invalid Encrypt structure");

    byte[] rgb = obj.EncodeToBytes();
    COSEObject msg = COSEObject.DecodeFromBytes(rgb, COSEObjectTag.Encrypt);
  }

  @Test
  public void encryptDecodeBadProtected() throws CoseException {
    CBORObject obj = CBORObject.NewArray();
    obj.Add(CBORObject.False);
    obj.Add(CBORObject.False);
    obj.Add(CBORObject.False);
    obj.Add(CBORObject.False);

    thrown.expect(CoseException.class);
    thrown.expectMessage("Invalid Encrypt structure");

    byte[] rgb = obj.EncodeToBytes();
    COSEObject msg = COSEObject.DecodeFromBytes(rgb, COSEObjectTag.Encrypt);
  }

  @Test
  public void encryptDecodeBadProtected2() throws CoseException {
    CBORObject obj = CBORObject.NewArray();
    obj.Add(CBORObject.FromObject(CBORObject.False));
    obj.Add(CBORObject.False);
    obj.Add(CBORObject.False);
    obj.Add(CBORObject.False);

    thrown.expect(CoseException.class);
    thrown.expectMessage("Invalid Encrypt structure");

    byte[] rgb = obj.EncodeToBytes();
    COSEObject msg = COSEObject.DecodeFromBytes(rgb, COSEObjectTag.Encrypt);
  }

  @Test
  public void encryptDecodeBadUnprotected() throws CoseException {
    CBORObject obj = CBORObject.NewArray();
    obj.Add(CBORObject.FromObject(CBORObject.NewArray()).EncodeToBytes());
    obj.Add(CBORObject.False);
    obj.Add(CBORObject.False);
    obj.Add(CBORObject.False);

    thrown.expect(CoseException.class);
    thrown.expectMessage("Invalid Encrypt structure");

    byte[] rgb = obj.EncodeToBytes();
    COSEObject msg = COSEObject.DecodeFromBytes(rgb, COSEObjectTag.Encrypt);
  }

  @Test
  public void encryptDecodeBadContent() throws CoseException {
    CBORObject obj = CBORObject.NewArray();
    obj.Add(CBORObject.FromObject(CBORObject.NewArray()).EncodeToBytes());
    obj.Add(CBORObject.NewMap());
    obj.Add(CBORObject.False);
    obj.Add(CBORObject.False);

    thrown.expect(CoseException.class);
    thrown.expectMessage("Invalid Encrypt structure");

    byte[] rgb = obj.EncodeToBytes();
    COSEObject msg = COSEObject.DecodeFromBytes(rgb, COSEObjectTag.Encrypt);
  }

  @Test
  public void encryptDecodeBadRecipients() throws CoseException {
    CBORObject obj = CBORObject.NewArray();
    obj.Add(CBORObject.FromObject(CBORObject.NewArray()).EncodeToBytes());
    obj.Add(CBORObject.NewMap());
    obj.Add(new byte[0]);
    obj.Add(CBORObject.False);

    thrown.expect(CoseException.class);
    thrown.expectMessage("Invalid Encrypt structure");

    byte[] rgb = obj.EncodeToBytes();
    COSEObject msg = COSEObject.DecodeFromBytes(rgb, COSEObjectTag.Encrypt);
  }
}
