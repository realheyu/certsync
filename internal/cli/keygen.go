package cli

import (
	"fmt"

	"github.com/spf13/cobra"

	"github.com/hy/certsync/internal/cryptoutil"
)

func newKeygenCmd() *cobra.Command {
	var out string
	cmd := &cobra.Command{
		Use:   "keygen",
		Short: "生成 32 字节主密钥(base64 写入 0600 文件,带外分发,3 节)",
		RunE: func(cmd *cobra.Command, args []string) error {
			if out == "" {
				return fmt.Errorf("必须指定 --out")
			}
			key, err := cryptoutil.GenerateKey()
			if err != nil {
				return err
			}
			if err := cryptoutil.WriteKeyFile(out, key); err != nil {
				return err
			}
			fmt.Fprintf(cmd.OutOrStdout(), "主密钥已写入 %s(0600)。请通过带外渠道分发到所有机器的 /etc/certsync/certsync.key\n", out)
			return nil
		},
	}
	cmd.Flags().StringVar(&out, "out", "", "输出文件路径(必填)")
	return cmd
}
