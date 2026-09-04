package repohealer

type Executor interface {
	Run(command string) (string, error)
	RunSudo(script string) (string, error)
	RunSudoWithLabel(script, label string) (string, error)
}
