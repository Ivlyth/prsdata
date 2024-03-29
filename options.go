package main

import (
	"bytes"
	"fmt"
	"github.com/mitchellh/go-homedir"
	logger "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
	"github.com/spf13/viper"
	"io/ioutil"
	"os"
	"strings"
	"time"
)

var (
	V                = viper.New()
	vConfig          *viper.Viper
	vTool            *viper.Viper
	vDefaultModifier *viper.Viper
	vDefaultFinder   *viper.Viper
	hasConfigFile    = false

	defaultConfigFile, _ = homedir.Expand("~/.prsdata.yml")

	completionCmd = &cobra.Command{
		Use:   "completion [bash|zsh|fish|powershell]",
		Short: "Generate completion script",
		Long: `To load completions:

Bash:

  $ source <(prsdata completion bash)

  # To load completions for each session, execute once:
  # Linux:
  $ prsdata completion bash > /etc/bash_completion.d/prsdata
  # macOS:
  $ prsdata completion bash > /usr/local/etc/bash_completion.d/prsdata

Zsh:

  # If shell completion is not already enabled in your environment,
  # you will need to enable it.  You can execute the following once:

  $ echo "autoload -U compinit; compinit" >> ~/.zshrc

  # To load completions for each session, execute once:
  $ prsdata completion zsh > "${fpath[1]}/_prsdata"

  # You will need to start a new shell for this setup to take effect.

fish:

  $ prsdata completion fish | source

  # To load completions for each session, execute once:
  $ prsdata completion fish > ~/.config/fish/completions/prsdata.fish

PowerShell:

  PS> prsdata completion powershell | Out-String | Invoke-Expression

  # To load completions for every new session, run:
  PS> prsdata completion powershell > prsdata.ps1
  # and source this file from your PowerShell profile.
`,
		DisableFlagsInUseLine: true,
		ValidArgs:             []string{"bash", "zsh", "fish", "powershell"},
		Args:                  cobra.ExactValidArgs(1),
		Run: func(cmd *cobra.Command, args []string) {
			switch args[0] {
			case "bash":
				cmd.Root().GenBashCompletion(os.Stdout)
			case "zsh":
				cmd.Root().GenZshCompletion(os.Stdout)
			case "fish":
				cmd.Root().GenFishCompletion(os.Stdout, true)
			case "powershell":
				cmd.Root().GenPowerShellCompletionWithDesc(os.Stdout)
			}
		},
	}

	rootCmd = &cobra.Command{
		Use:   fmt.Sprintf("prsdata (%s)", VERSION),
		Short: "find, modify and replay with pcap",
		Run: func(cmd *cobra.Command, args []string) {
			parseArgs(cmd)

			if config.Debug {
				dumpConfig()
			}

			run()
		},
	}
)

func init() {

	rootCmd.AddCommand(completionCmd)

	rootCmd.Flags().StringP("config-file", "f", defaultConfigFile, "配置文件路径")
	// default control params
	rootCmd.Flags().IntP("concurrency-jobs", "C", 1, "并发 job 数量")
	rootCmd.Flags().IntP("concurrency-commands", "c", 6, "并发 command 数量")
	rootCmd.Flags().IntP("test-times", "T", 1, "测试轮数")
	rootCmd.Flags().Bool("debug", false, "debug mode")
	rootCmd.Flags().DurationP("duration", "D", 0, "最大运行时长, 0 表示不限制, 可以使用诸如 1h3m5s 的表达式")
	rootCmd.Flags().DurationP("command-timeout", "S", 30*time.Second, "默认的单个命令执行时长")
	rootCmd.Flags().StringP("temporary-directory", "w", "/data/.prsdata/history/", "默认的临时文件夹")
	rootCmd.Flags().BoolP("just-show-jobs", "J", false, "仅打印加载的 job 列表")
	rootCmd.Flags().BoolP("just-show-pcaps", "j", false, "仅打印加载的 pcap 列表")
	rootCmd.Flags().Bool("show-command", false, "打印正在执行的命令")
	rootCmd.Flags().Bool("show-stdout", false, "打印正在执行的命令及其输出")
	rootCmd.Flags().Bool("show-why", false, "展示 pcap 未被加载的原因")
	rootCmd.Flags().Bool("keep-data", false, "是否保留数据")
	rootCmd.Flags().StringSliceP("jobs", "O", nil, "仅执行指定 ID 对应的 job, 逗号分割")
	rootCmd.Flags().Bool("daemon", false, "作为 daemon 在后台运行")
	rootCmd.Flags().String("pingback", "", "daemon 模式自动指定, 请勿手动指定")
	rootCmd.Flags().String("fast-copy", "", "快捷任务, 将查找到的 pcap 修改后拷贝到给定的目录下")
	rootCmd.Flags().String("fast-merge", "", "快捷任务, 将查找到的 pcap 修改后合并保存为指定路径的 pcap")
	rootCmd.Flags().StringToString("vars", map[string]string{}, "设定自定义变量的值用于命令渲染, 比如 --vars a=b, 可多次使用")
	rootCmd.Flags().Uint16("profile", 0, "pprof http server port, 0 means disable")
	rootCmd.Flags().BoolP("quiet", "q", false, "keep quiet")

	// default modifier params
	rootCmd.Flags().BoolP("adjust-time", "a", true, "adjust time or not")
	rootCmd.Flags().DurationP("time-offset", "t", 0, "time offset")
	rootCmd.Flags().BoolP("keep-ip", "K", false, "keep ip or not")
	rootCmd.Flags().Int("c1", 192, "c1")
	rootCmd.Flags().Int("c2", 168, "c2")
	rootCmd.Flags().Int("c3", 186, "c3")
	rootCmd.Flags().Int("c4", 11, "c4")
	rootCmd.Flags().Int("s1", 10, "s1")
	rootCmd.Flags().Int("s2", 132, "s2")
	rootCmd.Flags().Int("s3", 123, "s3")
	rootCmd.Flags().Int("s4", 22, "s4")
	rootCmd.Flags().BoolP("use-part-3", "3", false, "use part 3 or not")
	rootCmd.Flags().BoolP("use-part-4", "4", false, "use part 4 or not")
	rootCmd.Flags().BoolP("p426", "6", false, "将 IPv4 的 pcap 修改为 IPv6")
	rootCmd.Flags().IntP("shuffle-payload", "s", 0, "保留指定字节数后随机打乱剩余 payload")
	rootCmd.Flags().StringP("shuffle-packet", "r", "false", "默认将除了前 3 个 和 后 4 个以外的 packet 全部打乱, 可以使用 n:m 进行覆盖")
	rootCmd.Flags().StringP("tshark-filter", "R", "", "tshark 的 Read filter, modifier 会根据该 filter 生成一个新的 pcap 供后续处理")

	// default finder params
	rootCmd.Flags().StringP("directory", "d", "/data/.prsdata/pcaps/", "pcap search directory")
	rootCmd.Flags().StringSliceP("patterns", "p", nil, "patterns for filter pcap")
	rootCmd.Flags().StringArrayP("tags", "G", nil, "使用 tags 来筛选 pcap")
	rootCmd.Flags().Int("pps-le", 0, "pps less than or equal to given value")
	rootCmd.Flags().Int("pps-ge", 0, "pps greater than or equal to given value")
	rootCmd.Flags().Int("packet-count-le", 0, "packet count less than or equal to given value")
	rootCmd.Flags().Int("packet-count-ge", 0, "packet count greater than or equal to given value")
	rootCmd.Flags().Int("avg-packet-size-le", 0, "avg packet size less than or equal to given value")
	rootCmd.Flags().Int("avg-packet-size-ge", 0, "avg packet size greater than or equal to given value")
	rootCmd.Flags().Bool("only-ipv6", false, "find only ipv6 pcap")
	rootCmd.Flags().BoolP("only-ethernet", "E", true, "find only ethernet pcap")
	rootCmd.Flags().StringP("tshark-read-filter", "F", "", "tshark 的 Read filter, finder 主要根据该 filter 后的 pcap 的 packet 数量决定是否进一步处理该 pcap")

	// default tool path params
	rootCmd.Flags().String("bash", "bash", "bash binary path")
	rootCmd.Flags().String("capinfos", "capinfos", "capinfos binary path")
	rootCmd.Flags().String("editcap", "editcap", "editcap binary path")
	rootCmd.Flags().String("tcpdump", "tcpdump", "tcpdump binary path")
	rootCmd.Flags().String("tcprewrite", "tcprewrite", "tcprewrite binary path")
	rootCmd.Flags().String("tcpprep", "tcpprep", "tcpprep binary path")
	rootCmd.Flags().String("tshark", "tshark", "tshark binary path")
	rootCmd.Flags().String("mergecap", "mergecap", "mergecap binary path")

	rootCmd.Flags().BoolP("version", "V", false, "show version")

	rootCmd.Flags().SortFlags = false

	V.SetConfigType("yaml")

}

func parseArgs(cmd *cobra.Command) {
	showVersion, _ := cmd.Flags().GetBool("version")
	if showVersion {
		fmt.Printf("Version: %s\nCommit: %s\nCompile at: %s\nCompiled by: %s\n",
			VERSION, COMMIT, COMPILE_AT, GOVERSION)
		exit(0)
	}

	configFile, _ := cmd.Flags().GetString("config-file")
	if configFile == "" {
		logger.Warnln("config file path empty, will not use any config file")
	} else {
		stat, err := os.Stat(configFile)
		if err != nil {
			// allow default config file not exists
			if configFile != defaultConfigFile {
				logger.Errorln("config file does not exits")
				errorHappened = true
				terminate()
			}
		} else {
			if stat.IsDir() {
				logger.Errorf("\"%s\" is not a regular file\n", configFile)
				errorHappened = true
				terminate()
			}

			buf, err1 := ioutil.ReadFile(configFile)
			if err1 != nil {
				logger.Errorf("error when read from config file %s, %s\n", configFile, err1)
				errorHappened = true
				terminate()
			}

			err = V.ReadConfig(bytes.NewBuffer(buf))
			if err != nil {
				logger.Errorf("error when parse config file: %s\n", err)
				errorHappened = true
				terminate()
			}

			hasConfigFile = true
		}
	}

	V.SetDefault("config", map[string]interface{}{})
	V.SetDefault("config.tool", map[string]interface{}{})
	V.SetDefault("config.modifier", map[string]interface{}{})
	V.SetDefault("config.finder", map[string]interface{}{})
	vConfig = V.Sub("config")
	vTool = V.Sub("config.tool")
	vDefaultModifier = V.Sub("config.modifier")
	vDefaultFinder = V.Sub("config.finder")

	cmd.Flags().VisitAll(func(flag *pflag.Flag) {
		_ = vConfig.BindPFlag(strings.ReplaceAll(flag.Name, "-", "_"), cmd.Flags().Lookup(flag.Name))
		_ = vTool.BindPFlag(strings.ReplaceAll(flag.Name, "-", "_"), cmd.Flags().Lookup(flag.Name))
		_ = vDefaultModifier.BindPFlag(strings.ReplaceAll(flag.Name, "-", "_"), cmd.Flags().Lookup(flag.Name))
		_ = vDefaultFinder.BindPFlag(strings.ReplaceAll(flag.Name, "-", "_"), cmd.Flags().Lookup(flag.Name))
	})

	_ = vConfig.Unmarshal(config)
	_ = vTool.Unmarshal(pcapTool)
	_ = vDefaultModifier.Unmarshal(defaultModifier)
	_ = vDefaultFinder.Unmarshal(defaultFinder)

	// update logger log level
	if config.Debug {
		logger.SetLevel(logger.DebugLevel)
	} else if config.Quiet {
		logger.SetLevel(logger.FatalLevel)
	}

	if config.ProfilePort > 0 {
		startProfileServer(config.ProfilePort)
	}

	// fix default finder & modifier
	if defaultModifier.Id == "" {
		defaultModifier.Id = "default"
	}

	if defaultFinder.Id == "" {
		defaultFinder.Id = "default"
	}
	if defaultFinder.ModifierId == "" {
		defaultFinder.ModifierId = "default"
	}

	parseConfig()
}

func parseConfig() {

	check(config)
	check(pcapTool)

	// try to load another modifiers & finders
	ms := []*Modifier{}
	_ = V.UnmarshalKey("modifiers", &ms)
	ms = append(ms, defaultModifier)
	for i, m := range ms {
		if m == nil {
			logger.Errorf("auto check failed: modifier at index %d is null", i)
			errorHappened = true
			terminate()
		}
		check(m)
		modifiers[m.Id] = m
	}

	fs := []*Finder{}
	_ = V.UnmarshalKey("finders", &fs)
	fs = append(fs, defaultFinder)
	for i, f := range fs {
		if f == nil {
			logger.Errorf("auto check failed: finder at index %d is null", i)
			errorHappened = true
			terminate()
		}
		check(f)
		finders[f.Id] = f
	}

	js := []*Job{}

	if config.FastCopyDirectory != "" {
		config.SelectedJobs = []string{"fast-copy"}
		js = append(js, fastCopyJob(config.FastCopyDirectory))
	} else if config.FastMergePcapPath != "" {
		config.SelectedJobs = []string{"fast-merge"}
		js = append(js, fastMergeJob(config.FastMergePcapPath))
	} else {
		_ = V.UnmarshalKey("jobs", &js)

		if len(js) == 0 {
			js = append(js, defaultJobs()...)

			if len(config.SelectedJobs) == 0 { // use default jobs, but no selected job
				logger.Warnln(fmt.Sprintf("The default job must be explicitly enabled by -O XXX,YYY flag, available jobs are:"))
				for _, job := range js {
					logger.Warnln(fmt.Sprintf("- %s", job.Id))
				}
			}
		}
	}

	for i, j := range js {
		if j == nil {
			logger.Errorln(fmt.Sprintf("auto check failed: job at index %d is null", i))
			errorHappened = true
			terminate()
		}
		check(j)
		jobs[j.Id] = j
	}
}
