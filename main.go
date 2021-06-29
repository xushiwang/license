package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"
)

const (
	PRIKEY = "private.pem"
	PUBKEY = "public.pem"
)

func main() {
	// 生成公钥和私钥
	buf, err := readKeyFile(PRIKEY)
	if err != nil {
		// 私钥不存在 生成并保存
		privateKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		err = savePirvateKey(privateKey)
		if err != nil {
			fmt.Println(err)
			return
		}
		err = savePublicKey(privateKey.PublicKey)
		if err != nil {
			fmt.Println(err)
			return
		}
		// 重新读入数据
		buf, err = readKeyFile(PRIKEY)
	}
	//============================================
	// 解码数据流
	block, _ := pem.Decode(buf)
	// 还原成私钥
	privateKey, err := x509.ParseECPrivateKey(block.Bytes)
	if err != nil {
		fmt.Println(err)
		return
	}
	//============================================
	buffer, err := readKeyFile(PUBKEY)
	// 解码数据流
	b, _ := pem.Decode(buffer)
	// 还原成私钥
	publicKey, err := x509.ParsePKIXPublicKey(b.Bytes)
	if err != nil {
		fmt.Println(err)
		return
	}
	//============================================
	msg := []byte("dsa签名")
	// 对message进入签名操作
	r, s, _ := ecdsa.Sign(rand.Reader, privateKey, msg)
	switch Key := publicKey.(type) {
	case *ecdsa.PublicKey:
		fmt.Println(ecdsa.Verify(Key, msg, r, s), "数据未被修改")
	default:
		fmt.Println(false, "数据已被修改")
	}
}

func readKeyFile(keyFile string) ([]byte, error) {
	file, err := os.Open(keyFile)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	fileInfo, err := file.Stat()
	if err != nil {
		panic("file.Stat err!")
	}
	buf := make([]byte, fileInfo.Size())
	file.Read(buf)
	return buf, nil
}

func savePirvateKey(p *ecdsa.PrivateKey) error {
	priByte, err := x509.MarshalECPrivateKey(p)
	if err != nil {
		return err
	}
	block := pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: priByte,
	}
	file, err := os.Create("private.pem")
	if err != nil {
		return err
	}
	defer file.Close()
	// 写入私钥到文件存储
	err = pem.Encode(file, &block)
	if err != nil {
		fmt.Println("写入私钥到文件出错了")
		return err
	}
	return nil
}

func savePublicKey(publicKey ecdsa.PublicKey) error {
	pub, err := x509.MarshalPKIXPublicKey(&publicKey)
	if err != nil {
		return err
	}
	block := pem.Block{
		Type:  "PUBLICK KEY",
		Bytes: pub,
	}

	file, err := os.Create("public.pem")
	if err != nil {
		return err
	}
	defer file.Close()
	// 写入私钥到文件存储
	err = pem.Encode(file, &block)
	if err != nil {
		fmt.Println("写入公钥到文件出错了")
		return err
	}
	return nil
}
