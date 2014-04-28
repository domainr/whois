package whois

type Fetcher func(string) (*Response, error)

func Fetch(query string) (*Response, error) {
	fetcher, err := selectFetcher(query)
	if err != nil {
		return nil, err
	}
	return fetcher(query)
}

func selectFetcher(query string) (Fetcher, error) {
	
}
